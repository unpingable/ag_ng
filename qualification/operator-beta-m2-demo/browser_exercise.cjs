#!/usr/bin/env node
'use strict';

// Observational qualification driver. Docket owns launch, state and terminality.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const os = require('node:os');
const {parseArgs} = require('node:util');
const {values: opts} = parseArgs({options: {
  url: {type:'string'}, out: {type:'string'}, mode: {type:'string'},
  action: {type:'string', default:'observe'},
  'max-seconds': {type:'string', default:'60'},
  'expect-state': {type:'string'}, 'expect-live': {type:'string'},
  'expect-disposition': {type:'string'}, 'repeat-run': {type:'boolean', default:false},
  'wait-terminal': {type:'boolean', default:false},
  'expect-outage-after-good': {type:'boolean', default:false},
  browser: {type:'string', default:process.env.M2_BROWSER_EXECUTABLE || '/snap/bin/chromium'},
  playwright: {type:'string', default:process.env.M2_PLAYWRIGHT_MODULE || '/data/git/agent_gov_ui/marginalia/node_modules/playwright'},
}});
assert(['LIVE_INTEGRATION','DISPLAY_FIXTURE'].includes(opts.mode), 'explicit evidence mode required');
assert(['launch','observe'].includes(opts.action), 'action must be launch or observe');
assert(opts.out && path.isAbsolute(opts.out), 'absolute new capture directory required');
const url = new URL(opts.url);
assert(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.pathname === '/' && !url.search && !url.hash && !url.username && !url.password, 'fixed numeric-loopback URL required');
const seconds = Number(opts['max-seconds']);
assert(Number.isInteger(seconds) && seconds > 0 && seconds <= 7200, 'explicit bound must be 1..7200 seconds');
assert(!opts['repeat-run'] || opts.action === 'launch', 'repeat-run requires explicit launch exercise');
fs.mkdirSync(opts.out, {mode:0o700}); // Existing output is never overwritten.
const eventFile = path.join(opts.out,'browser-observations.jsonl');
function write(name, bytes) {
  const fd = fs.openSync(path.join(opts.out,name),'wx',0o600);
  try {fs.writeFileSync(fd,bytes); fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
}
function event(kind, fields={}) {
  const fd = fs.openSync(eventFile,'a',0o600);
  try {fs.writeSync(fd,JSON.stringify({time:new Date().toISOString(),mode:opts.mode,source:'browser qualification observer',kind,...fields})+'\n'); fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
}
function sha(bytes) {return crypto.createHash('sha256').update(bytes).digest('hex');}
let browser, context, page, count=0, subject, boundProducer, last, lastMotion;
const started = Date.now();
function remaining() {
  const ms = seconds*1000-(Date.now()-started);
  if (ms <= 0) throw Error('Capture bound exhausted; campaign outcome not inferred');
  return Math.min(ms,150000);
}
async function open() {
  context = await browser.newContext({viewport:{width:1280,height:1100}});
  page = await context.newPage();
  // Fixture pages carry an unmistakable observer label in every screenshot.
  await page.addInitScript(mode => document.addEventListener('DOMContentLoaded',()=>{
    if(mode==='DISPLAY_FIXTURE') {
      const label=document.createElement('p'); label.textContent='DISPLAY FIXTURE — no integration qualification';
      label.style='position:sticky;top:0;background:#ffdf80;padding:12px;font-weight:bold;z-index:100'; document.body.prepend(label);
    }
  }),opts.mode);
  await page.goto(url.href,{waitUntil:'domcontentloaded',timeout:remaining()});
  await page.locator('#durable').waitFor({timeout:remaining()});
}
async function sample(label, assertRender=false) {
  remaining();
  const response = await context.request.get(new URL('/api/v1/status',url).href,{timeout:remaining()});
  const bytes = await response.body();
  assert(bytes.length <= 1024*1024,'bounded status response');
  let value;
  try {value=JSON.parse(bytes.toString('utf8'));}
  catch(error) {write('unparseable-status.raw',bytes); throw Error('Owner HTTP projection is not parseable JSON; raw bytes retained');}
  const motion=JSON.stringify([value.subject,value.runner_durable,value.controller_custody,value.liveness?.state,
    value.liveness?.main_pid,value.liveness?.start_ticks,value.disagreements]);
  if(label==='progress' && response.status()===200 && motion===lastMotion) {last=value; return value;}
  lastMotion=motion;
  const index=String(count++).padStart(4,'0');
  write(`${index}-${label}.status.json`,bytes);
  if(response.status() !== 200) {
    await page.waitForFunction(()=>document.querySelector('#notice').textContent.includes('NOT_OBSERVABLE')
      && document.querySelector('#live').textContent==='NOT_OBSERVABLE'
      && document.querySelector('#run').disabled,null,{timeout:Math.min(10000,remaining())});
    await page.screenshot({path:path.join(opts.out,`${index}-${label}.png`),fullPage:true,timeout:remaining()});
    event('SourceUnavailable',{http_status:response.status(),status_sha256:sha(bytes)});
    throw Error('Owner projection unavailable; raw response retained, no campaign outcome inferred');
  }
  assert.equal(value.schema,'constellation.operator_beta.fixed_demo_status.v1');
  assert.equal(typeof value.subject.run_id,'string');
  assert.equal(typeof value.subject.spec_sha256,'string');
  const currentSubject=JSON.stringify([value.subject.run_id,value.subject.spec_sha256]);
  if(subject) assert.equal(currentSubject,subject,'same admitted occurrence across all browser operations');
  subject=currentSubject;
  const producer=value.runner_durable.recovery?.producer;
  if(producer) {
    const identity=JSON.stringify([producer.systemd_unit,producer.invocation_id,producer.main_pid,producer.start_ticks]);
    if(boundProducer) assert.equal(identity,boundProducer,'reconnect or repeated RUN changed producer occurrence');
    boundProducer=identity;
  }
  if(assertRender) {
    await page.waitForFunction(expected=>{
      const text=id=>document.getElementById(id).textContent;
      const terminal=expected.runner_durable.terminal;
      const ready=expected.controller_custody.state==='NO_INTENT_RECORDED' && expected.disagreements.length===0;
      return text('durable')===expected.runner_durable.state && text('live').includes(expected.liveness.state)
        && text('custody').includes(expected.controller_custody.state)
        && document.getElementById('run').disabled===!ready
        && expected.disagreements.every(reason=>text('notice').includes(reason))
        && (terminal ? text('terminal')===(terminal.disposition||terminal.state)
          && (!terminal.evidence || text('receipt').includes(terminal.evidence)
            && text('receipt').includes(terminal.owner) && text('receipt').includes(terminal.validator))
          : text('terminal').includes('No validated terminal'));
    },value,{timeout:Math.min(10000,remaining())});
  }
  const dom=await page.locator('body').innerText({timeout:remaining()});
  write(`${index}-${label}.rendered.txt`,dom);
  await page.screenshot({path:path.join(opts.out,`${index}-${label}.png`),fullPage:true,timeout:remaining()});
  event('ProjectionObserved',{label,http_status:response.status(),status_sha256:sha(bytes),run_id:value.subject.run_id,
    durable:value.runner_durable.state,liveness:value.liveness.state,custody:value.controller_custody.state});
  last=value;
  return value;
}
async function main() {
  const {chromium}=require(opts.playwright);
  write('CAPTURE-INPUTS.json',JSON.stringify({mode:opts.mode,source:'browser qualification observer',url:url.href,action:opts.action,
    host:os.hostname(),working_directory:process.cwd(),pid:process.pid,started_at:new Date(started).toISOString(),
    invocation_id:process.env.INVOCATION_ID || 'NOT_OBSERVABLE',
    max_seconds:seconds,repeat_run:opts['repeat-run'],wait_terminal:opts['wait-terminal'],node:process.version,
    driver_sha256:sha(fs.readFileSync(__filename)),playwright_module:opts.playwright,
    browser_launcher:opts.browser,browser_launcher_sha256:sha(fs.readFileSync(opts.browser)),
    authority_effect:'NONE; explicit RUN delegates to existing Docket owner'},null,2)+'\n');
  browser=await chromium.launch({executablePath:opts.browser,headless:true,chromiumSandbox:true,timeout:remaining()});
  event('BrowserStarted',{version:browser.version()});
  await open();
  await sample('initial',true);
  if(opts['expect-outage-after-good']) {
    assert.equal(opts.mode,'DISPLAY_FIXTURE','outage transition is display qualification only');
    assert(last.runner_durable.terminal?.evidence,'start from an observed receipt');
    await page.waitForFunction(()=>['durable','live','live-detail','terminal','reason','custody','worker','execution-detail','evidence','next','receipt','sources','limits']
      .every(id=>document.getElementById(id).textContent==='NOT_OBSERVABLE') && document.getElementById('run').disabled,
      null,{timeout:Math.min(12000,remaining())});
    const response=await context.request.get(new URL('/api/v1/status',url).href,{timeout:remaining()});
    assert.equal(response.status(),503);
    write('outage.status.json',await response.body());
    write('outage.rendered.txt',await page.locator('body').innerText());
    await page.screenshot({path:path.join(opts.out,'outage.png'),fullPage:true});
    write('CAPTURE-COMPLETED.json',JSON.stringify({state:'GOOD_TO_OUTAGE_ASSERTIONS_PASSED',mode:opts.mode,
      current_regions:'ALL_NOT_OBSERVABLE',qualification:'NOT_GRANTED_BY_BROWSER_DRIVER'},null,2)+'\n');
    event('GoodToOutageValidated');
    return;
  }
  if(opts.action==='launch') {
    assert.equal(last.controller_custody.state,'NO_INTENT_RECORDED','launch only from owner ready state');
    assert.equal(last.disagreements.length,0);
    await page.locator('#run').click({timeout:remaining()});
    await page.waitForLoadState('domcontentloaded',{timeout:remaining()});
    event('RunClicked');
    await sample('after-run',true);
    assert.notEqual(last.controller_custody.state,'NO_INTENT_RECORDED','RUN must obtain retained custody or expose uncertainty');
    if(opts['repeat-run']) {
      // Deliberate qualification requests: existing owner must reuse one intent.
      const replies=await page.evaluate(async()=>Promise.all([0,1].map(async()=>{
        const form=document.querySelector('form');
        const reply=await fetch('/run',{method:'POST',body:new URLSearchParams(new FormData(form)),redirect:'follow'});
        return reply.status;
      })));
      event('RepeatedRunRequests',{http_statuses:replies});
      await sample('after-repeated-run',true);
    }
  }
  await page.reload({waitUntil:'domcontentloaded',timeout:remaining()});
  await sample('refresh',true);
  await context.close();
  event('BrowserContextDisconnected');
  await open();
  await sample('reconnect',true);
  if(opts['wait-terminal']) {
    while(!['TERMINAL','REFUSED'].includes(last.runner_durable.terminal?.state)) {
      await page.waitForTimeout(Math.min(3000,remaining()));
      await sample('progress');
    }
    await sample('terminal',true);
  }
  if(opts['expect-state']) assert.equal(last.runner_durable.state,opts['expect-state']);
  if(opts['expect-live']) assert.equal(last.liveness.state,opts['expect-live']);
  if(opts['expect-disposition']) assert.equal(last.runner_durable.terminal?.disposition,opts['expect-disposition']);
  write('CAPTURE-COMPLETED.json',JSON.stringify({state:'BROWSER_ASSERTIONS_PASSED',mode:opts.mode,subject:JSON.parse(subject),
    observed_owner_terminal:last.runner_durable.terminal,qualification:'NOT_GRANTED_BY_BROWSER_DRIVER',
    independent_owner_reopening_required:true,samples:count},null,2)+'\n');
  event('CaptureCompleted',{samples:count});
}
main().catch(error=>{
  write('CAPTURE-FAILED.json',JSON.stringify({state:'BROWSER_CAPTURE_INCOMPLETE_OR_ASSERTION_FAILED',mode:opts.mode,
    reason:error.message,qualification:'NOT_GRANTED',producer_action:'none; reopen existing owner evidence'},null,2)+'\n');
  event('CaptureFailed',{reason:error.message}); process.exitCode=1;
}).finally(async()=>{if(browser) await browser.close();});
