'use strict';
// Registered-issue coverage is bounded by chi/kappa; it is not real-world completeness.
const {m, ensure, same} = require('./io');
const schema = require('../chaincode/issues');
const sorted = values => [...values].sort((a,b) => a.recordID < b.recordID ? -1 : a.recordID > b.recordID ? 1 : 0);
function position(snapshot, id) {
  const p = snapshot.births.get(id);
  ensure(p && /^(0|[1-9][0-9]*)$/.test(p.block) && Number.isInteger(p.index) && p.index >= 0, 'MISSING_RECORD_BIRTH');
  return p;
}
function at(snapshot, checkpoint) {
  m.assertCheckpoint(checkpoint);
  ensure(snapshot.headers.some(h => h.number === checkpoint.blockNumber && h.hash === checkpoint.blockHeaderHash), 'ISSUE_CHECKPOINT_MISMATCH');
  return new Map([...snapshot.records].filter(([id]) => BigInt(position(snapshot,id).block) <= BigInt(checkpoint.blockNumber)));
}
function bodyCheck(record) {
  m.verifyEnvelopeCommitment(record);
  if (record.kind === 'ISSUE') schema.validateIssueBody(record.body, record.caseID);
  else if (record.kind === 'ISSUE_RESPONSE') schema.validateResponseBody(record.body, record.caseID, true);
  else if (record.kind === 'ISSUE_DISPOSITION') schema.validateDispositionBody(record.body, record.caseID, true);
  else throw new Error('NOT_AN_ISSUE_RECORD');
}
function eventsFor(records, issue) {
  const ref = m.recordRef(issue), found = [...records.values()].filter(e =>
    ['ISSUE_RESPONSE','ISSUE_DISPOSITION'].includes(e.kind) && e.body.issueRef.recordID === issue.recordID);
  found.forEach(e => {bodyCheck(e); ensure(same(e.body.issueRef,ref), 'ISSUE_EVENT_REFERENCE_MISMATCH');});
  return found.sort((a,b) => a.body.issueSeq - b.body.issueSeq);
}
function project(snapshot, records, issue) {
  const events = eventsFor(records,issue); let prior = position(snapshot,issue.recordID);
  for (const e of events) {
    const next=position(snapshot,e.recordID);
    ensure(BigInt(next.block)>BigInt(prior.block) || (next.block===prior.block && next.index>prior.index), 'ISSUE_EVENT_CHRONOLOGY');
    prior=next;
  }
  return schema.projectIssue(issue,events);
}
function basisContext(snapshot, request, materials) {
  const records=at(snapshot,request.body.checkpointBasis);
  const derived=require('./package').closure(records,request.body);
  ensure(same(materials,derived),'ISSUE_BASIS_ARGUMENT_MISMATCH');
  const refs=derived.map(e => m.materialRef(e));
  const issues=sorted([...records.values()].filter(e => e.kind==='ISSUE' &&
    refs.some(ref => same(ref,e.body.targetRef))));
  issues.forEach(e=>{bodyCheck(e); project(snapshot,records,e);});
  const issueEvents=sorted(issues.flatMap(e => eventsFor(records,e)));
  return {issues,issueEvents};
}
function coverage(actual,expected,label) {
  if(!Array.isArray(actual)) return {missing:expected.map(e=>e.recordID),unexpected:[],changed:[],reasonPaths:[label]};
  const ids=actual.map(e=>e?.recordID), wanted=new Map(expected.map(e=>[e.recordID,e]));
  const missing=expected.filter(e=>!ids.includes(e.recordID)).map(e=>e.recordID);
  const unexpected=ids.filter((id,i)=>!wanted.has(id)||ids.indexOf(id)!==i);
  const changed=actual.filter(e=>wanted.has(e?.recordID)&&!same(e,wanted.get(e.recordID))).map(e=>e.recordID);
  return {missing,unexpected,changed,reasonPaths:[...missing,...unexpected,...changed].map(id=>`${label}:${String(id)}`)};
}
function requireCoverage(actual,expected,label) {
  if(same(actual,expected)) return;
  const details=coverage(actual,expected,label);
  if(!details.reasonPaths.length) details.reasonPaths=[`${label}:ORDER`];
  const e=new Error('PACKAGE_ISSUE_CONTEXT_MISSING_OR_DIFFERENT');e.contextFailure=true;e.details=details;throw e;
}
function historySummary(snapshot,request,checkpoint,materials) {
  ensure(checkpoint.channelID===request.body.checkpointBasis.channelID,'HISTORY_CHANNEL_MISMATCH');
  ensure(BigInt(checkpoint.blockNumber)>BigInt(request.body.checkpointBasis.blockNumber),'HISTORY_MUST_FOLLOW_BASIS');
  const records=at(snapshot,checkpoint), reqRef=m.recordRef(request);
  ensure(records.has(request.recordID)&&same(records.get(request.recordID),request), 'REQUEST_OUTSIDE_HISTORY');
  ensure(BigInt(position(snapshot,request.recordID).block)>BigInt(request.body.checkpointBasis.blockNumber),'REQUEST_MUST_FOLLOW_BASIS');
  const basis=basisContext(snapshot,request,materials), selected=new Map(basis.issues.map(e=>[e.recordID,e]));
  for(const e of records.values()) if(e.kind==='ISSUE' &&
    (same(e.body.targetRef,reqRef) || (e.body.associatedRequestRef!==null && same(e.body.associatedRequestRef,reqRef)))) {
    bodyCheck(e); selected.set(e.recordID,e);
  }
  const relevant=new Map([[request.recordID,request]]);
  for(const e of records.values()) if((e.kind==='PACKAGE_RECORD'&&same(e.body.requestRef,reqRef)) ||
    (e.kind==='OBSERVATION'&&same(e.body.intendedRequestRef,reqRef))) relevant.set(e.recordID,e);
  const heads=[];
  for(const issue of sorted(selected.values())) {
    relevant.set(issue.recordID,issue);
    for(const e of eventsFor(records,issue)) relevant.set(e.recordID,e);
    heads.push(project(snapshot,records,issue));
  }
  const entries=[...relevant.values()].map(e=>({record:e,position:position(snapshot,e.recordID)})).sort((a,b)=>{
    const x=BigInt(a.position.block),y=BigInt(b.position.block);
    return x<y?-1:x>y?1:a.position.index-b.position.index||(a.record.recordID<b.record.recordID?-1:1);
  });
  return m.parseJson(m.canonicalJson({formatVersion:'LWFA_HISTORY_1',caseID:request.caseID,intendedRequestRef:reqRef,
    checkpointBasis:request.body.checkpointBasis,checkpointHistory:checkpoint,entries,issueHeads:heads}));
}
function verifyHistorySummary(presented,snapshot,request,checkpoint,materials) {
  const expected=historySummary(snapshot,request,checkpoint,materials);
  m.assertExactShape(presented,['formatVersion','caseID','intendedRequestRef','checkpointBasis','checkpointHistory','entries','issueHeads'],'historySummary');
  for(const k of ['formatVersion','caseID','intendedRequestRef','checkpointBasis','checkpointHistory'])
    ensure(same(presented[k],expected[k]),'HISTORY_BINDING_MISMATCH');
  ensure(Array.isArray(presented.entries) && presented.entries.every(e=>e&&e.record&&e.position) && Array.isArray(presented.issueHeads),'HISTORY_SCHEMA');
  const details=coverage(presented.entries.map(e=>e.record),expected.entries.map(e=>e.record),'history.entries');
  if(!same(presented.entries,expected.entries)&&!details.reasonPaths.length) details.reasonPaths.push('history.entries:ORDER_OR_POSITION');
  if(!same(presented.issueHeads,expected.issueHeads)) details.reasonPaths.push('history.issueHeads');
  return {historyStatus:details.reasonPaths.length?'UNSATISFIED':'SATISFIED',...details,
    meaning:'Coverage of registered records through the declared cutoff, not unrecorded attempts or substantive truth'};
}
module.exports={at,basisContext,historySummary,verifyHistorySummary,requireCoverage,coverage,eventsFor,project};
