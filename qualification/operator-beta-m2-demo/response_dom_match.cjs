'use strict';

// Correlate browser-observed source bytes with one atomic DOM observation.
// This checks rendering only; it grants no campaign disposition.
function matches(status, value, dom) {
  if (status !== 200) return dom.texts.notice.includes('NOT_OBSERVABLE')
    && dom.texts.live === 'NOT_OBSERVABLE' && dom.runDisabled;
  if (!value?.runner_durable || !value?.controller_custody || !value?.liveness
      || !Array.isArray(value.disagreements)) return false;
  const terminal = value.runner_durable.terminal;
  const ready = value.controller_custody.state === 'NO_INTENT_RECORDED' && value.disagreements.length === 0;
  if(dom.extra) {
    try {
      for(const [key,expected] of Object.entries({liveDetail:value.liveness,execution:value.execution,
        limits:value.limitations,sources:{disagreements:value.disagreements,live_sources:value.live_sources}})) {
        if(JSON.stringify(JSON.parse(dom.extra[key]))!==JSON.stringify(expected))return false;
      }
      if(dom.evidenceRows.length!==value.evidence.length)return false;
      if(!value.evidence.every((entry,index)=>{
        const row=dom.evidenceRows[index];
        return row.label===entry.label && row.source==='Source: '+entry.source+' · '+entry.state
          && row.reference===JSON.stringify({evidence:entry.evidence,detail:entry.detail},null,2);
      }))return false;
    } catch {return false;}
  }
  return dom.texts.durable === value.runner_durable.state
    && dom.texts.live === value.liveness.state
    && dom.texts.custody.includes(value.controller_custody.state)
    && dom.runDisabled === !ready
    && value.disagreements.every(reason => dom.texts.notice.includes(reason))
    && (terminal ? dom.texts.terminal === (terminal.disposition || terminal.state)
      && (!terminal.evidence || dom.texts.receipt.includes(terminal.evidence)
        && dom.texts.receipt.includes(terminal.owner) && dom.texts.receipt.includes(terminal.validator))
      : dom.texts.terminal.includes('No validated terminal'));
}

function select(observations, dom) {
  return [...observations].reverse().find(item => item.value && matches(item.status, item.value, dom));
}

module.exports = {matches, select};
