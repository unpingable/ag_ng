'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const {select} = require('./response_dom_match.cjs');
function response(phase) {return {status:200,bytes:Buffer.from(phase),value:{
  runner_durable:{state:phase,terminal:null},controller_custody:{state:'ACCEPTANCE_VALIDATED'},
  liveness:{state:'PROCESS_ACTIVE'},live_sources:{os:{state:'PROCESS_ACTIVE'}},disagreements:[]}};}
function dom(phase) {return {runDisabled:true,texts:{durable:phase,live:'PROCESS_ACTIVE',
  custody:'ACCEPTANCE_VALIDATED',notice:'',terminal:'NOT YET ESTABLISHED',receipt:''}};}
test('source advance selects exact browser response matching current DOM, not stale independent sample',()=>{
  const earlier=response('created'), later=response('guests_ready');
  assert.equal(select([earlier,later],dom('guests_ready')),later);
  assert.equal(select([earlier,later],dom('created')),earlier);
  assert.equal(select([earlier],dom('guests_ready')),undefined);
});
test('incorrect or mixed rendering cannot manufacture a matching observation',()=>{
  const displayed=dom('guests_ready');displayed.texts.live='PROCESS_EXITED';
  assert.equal(select([response('created'),response('guests_ready')],displayed),undefined);
  displayed.texts.live='PROCESS_ACTIVE';displayed.runDisabled=false;
  assert.equal(select([response('guests_ready')],displayed),undefined);
});
test('source failure only pairs with explicit unavailable rendering',()=>{
  const unavailable={status:503,value:{state:'NOT_OBSERVABLE'}};
  assert.equal(select([unavailable],dom('created')),undefined);
  const cleared=dom('NOT_OBSERVABLE');cleared.texts.live='NOT_OBSERVABLE';cleared.texts.notice='Current state NOT_OBSERVABLE';
  assert.equal(select([unavailable],cleared),unavailable);
});
