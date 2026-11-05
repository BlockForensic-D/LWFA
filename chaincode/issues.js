'use strict';
// M3 syntax and deterministic projection. No ledger I/O or identity claims.
const m = require('./model');
const clone = v => m.parseJson(m.canonicalJson(v));
const same = (a, b) => m.canonicalJson(a) === m.canonicalJson(b);
function demand(ok, code, field, message) { if (!ok) throw new m.LWFAError(code, field, message); }
function text(v, field) {
  demand(typeof v === 'string' && v.trim().length > 0 && v.length <= m.LIMITS.textChars,
    'SCHEMA_ERROR', field, 'nonempty bounded text required'); m.canonicalJson(v);
}
function sequence(v, field) {
  demand(Number.isInteger(v) && v >= 1 && v <= m.LIMITS.version, 'SCHEMA_ERROR', field, 'positive bounded sequence required');
}
function targetRef(ref, caseID) {
  if (ref && Object.hasOwn(ref, 'objectID')) m.assertMaterialRef(ref, caseID);
  else { m.assertRecordRef(ref, caseID); demand(ref.kind === 'REVIEW_REQUEST', 'INVALID_REFERENCE', 'targetRef', 'only material or REVIEW_REQUEST targets'); }
}
function issueRef(ref, caseID) {
  m.assertRecordRef(ref, caseID); demand(ref.kind === 'ISSUE', 'INVALID_REFERENCE', 'issueRef', 'ISSUE reference required');
}
function support(refs, caseID) {
  demand(Array.isArray(refs) && refs.length <= 100, 'SCHEMA_ERROR', 'supportRefs', 'at most 100 material references');
  return m.sortMaterialRefs(refs, caseID);
}
function validateIssueBody(raw, caseID) {
  const v = clone(raw);
  m.assertExactShape(v, ['issueType', 'targetRef', 'reasonCode', 'rationale', 'supportRefs', 'associatedRequestRef'], 'issue');
  demand(['LIMITATION', 'GAP', 'CHALLENGE'].includes(v.issueType), 'SCHEMA_ERROR', 'issueType', 'unsupported issue type');
  targetRef(v.targetRef, caseID); m.assertID(v.reasonCode, 'reasonCode'); text(v.rationale, 'rationale');
  v.supportRefs = support(v.supportRefs, caseID);
  if (v.associatedRequestRef !== null) {
    m.assertRecordRef(v.associatedRequestRef, caseID);
    demand(v.associatedRequestRef.kind === 'REVIEW_REQUEST', 'INVALID_REFERENCE', 'associatedRequestRef', 'REVIEW_REQUEST required');
  }
  if (v.targetRef.kind === 'REVIEW_REQUEST') {
    demand(v.associatedRequestRef === null || same(v.associatedRequestRef, v.targetRef),
      'INVALID_REFERENCE', 'associatedRequestRef', 'request target cannot be associated to another request');
  }
  if (v.reasonCode === 'SCOPE_INADEQUATE') demand(v.issueType === 'CHALLENGE' && v.targetRef.kind === 'REVIEW_REQUEST',
    'SCHEMA_ERROR', 'reasonCode', 'scope challenge requires a REVIEW_REQUEST target');
  return v;
}
function eventBody(raw, caseID, disposition, sealed) {
  const v = clone(raw);
  const keys = disposition ? ['issueRef', 'expectedIssueSeq', 'disposition', 'rationale', 'supportRefs'] : ['issueRef', 'statement', 'supportRefs'];
  m.assertExactShape(v, sealed ? [...keys, 'issueSeq', 'previousEventRef'] : keys, disposition ? 'disposition' : 'response');
  issueRef(v.issueRef, caseID); v.supportRefs = support(v.supportRefs, caseID);
  if (disposition) {
    sequence(v.expectedIssueSeq, 'expectedIssueSeq');
    demand(['WITHDRAWN', 'ADDRESSED', 'DISAGREEMENT'].includes(v.disposition), 'SCHEMA_ERROR', 'disposition', 'unsupported disposition');
    text(v.rationale, 'rationale');
  } else text(v.statement, 'statement');
  if (sealed) {
    sequence(v.issueSeq, 'issueSeq'); demand(v.issueSeq > 1, 'SCHEMA_ERROR', 'issueSeq', 'event follows initial issue');
    m.assertRecordRef(v.previousEventRef, caseID);
    demand(['ISSUE', 'ISSUE_RESPONSE', 'ISSUE_DISPOSITION'].includes(v.previousEventRef.kind),
      'INVALID_REFERENCE', 'previousEventRef', 'invalid issue event predecessor');
    if (disposition) demand(v.expectedIssueSeq === v.issueSeq - 1, 'STALE_ISSUE_BASIS', 'expectedIssueSeq', 'disposition must seal immediate basis');
  }
  return v;
}
const validateResponseBody = (v, c, sealed = false) => eventBody(v, c, false, sealed);
const validateDispositionBody = (v, c, sealed = false) => eventBody(v, c, true, sealed);
function input(raw, field, validate) {
  const v = clone(raw); m.assertExactShape(v, ['schemaVersion', 'caseID', 'operationID', 'recordID', field], 'input');
  demand(v.schemaVersion === m.SCHEMA_VERSION, 'SCHEMA_ERROR', 'schemaVersion', 'unsupported schema');
  for (const k of ['caseID', 'operationID', 'recordID']) m.assertID(v[k], k);
  v[field] = validate(v[field], v.caseID); return v;
}
const validateIssueInput = v => input(v, 'issue', validateIssueBody);
const validateResponseInput = v => input(v, 'response', validateResponseBody);
const validateDispositionInput = v => input(v, 'disposition', validateDispositionBody);
function initialHead(issue) {
  m.verifyEnvelopeCommitment(issue); demand(issue.kind === 'ISSUE', 'INVALID_REFERENCE', 'issue', 'ISSUE required');
  validateIssueBody(issue.body, issue.caseID);
  return {caseID: issue.caseID, issueRef: m.recordRef(issue), lastEventSeq: 1, lastEventRef: m.recordRef(issue),
    latestDispositionRef: null, status: issue.body.issueType === 'CHALLENGE' ? 'OPEN' : 'RECORDED'};
}
function validateHead(head, issue) {
  m.assertExactShape(head, ['caseID', 'issueRef', 'lastEventSeq', 'lastEventRef', 'latestDispositionRef', 'status'], 'issueHead');
  demand(head.caseID === issue.caseID && same(head.issueRef, m.recordRef(issue)), 'STATE_CORRUPT', 'issueHead', 'issue identity mismatch');
  sequence(head.lastEventSeq, 'issueHead.lastEventSeq'); m.assertRecordRef(head.lastEventRef, issue.caseID);
  demand(['ISSUE', 'ISSUE_RESPONSE', 'ISSUE_DISPOSITION'].includes(head.lastEventRef.kind), 'STATE_CORRUPT', 'issueHead.lastEventRef', 'invalid last event');
  const challenged = issue.body.issueType === 'CHALLENGE';
  demand((challenged ? ['OPEN', 'ANSWERED', 'WITHDRAWN', 'ADDRESSED', 'DISAGREEMENT'] : ['RECORDED']).includes(head.status),
    'STATE_CORRUPT', 'issueHead.status', 'invalid projection');
  if (head.latestDispositionRef !== null) {
    m.assertRecordRef(head.latestDispositionRef, issue.caseID);
    demand(challenged && head.latestDispositionRef.kind === 'ISSUE_DISPOSITION' && ['WITHDRAWN','ADDRESSED','DISAGREEMENT'].includes(head.status),
      'STATE_CORRUPT', 'issueHead.latestDispositionRef', 'invalid disposition projection');
  } else demand(!['WITHDRAWN','ADDRESSED','DISAGREEMENT'].includes(head.status), 'STATE_CORRUPT', 'issueHead.status', 'missing disposition');
  if (head.lastEventSeq === 1) demand(same(head, initialHead(issue)), 'STATE_CORRUPT', 'issueHead', 'invalid initial projection');
  return clone(head);
}
function applyEvent(head, issue, event) {
  validateHead(head, issue); m.verifyEnvelopeCommitment(event);
  demand(event.caseID === issue.caseID, 'CASE_MISMATCH', 'event', 'foreign issue event');
  demand(['ISSUE_RESPONSE', 'ISSUE_DISPOSITION'].includes(event.kind), 'INVALID_REFERENCE', 'event.kind', 'invalid event kind');
  const disposition = event.kind === 'ISSUE_DISPOSITION';
  const b = disposition ? validateDispositionBody(event.body, issue.caseID, true) : validateResponseBody(event.body, issue.caseID, true);
  demand(same(b.issueRef, m.recordRef(issue)) && b.issueSeq === head.lastEventSeq + 1 && same(b.previousEventRef, head.lastEventRef),
    'ISSUE_HISTORY_MISMATCH', 'event', 'missing, reordered or foreign issue event');
  const next = {...head, lastEventSeq: b.issueSeq, lastEventRef: m.recordRef(event)};
  if (disposition) {
    demand(issue.body.issueType === 'CHALLENGE', 'INVALID_ISSUE_TYPE', 'issueType', 'only CHALLENGE has dispositions');
    next.latestDispositionRef = m.recordRef(event); next.status = b.disposition;
  } else if (issue.body.issueType === 'CHALLENGE' && head.latestDispositionRef === null) next.status = 'ANSWERED';
  return validateHead(next, issue);
}
function projectIssue(issue, events) {
  let head = initialHead(issue);
  for (const event of [...events].sort((a, b) => a.body.issueSeq - b.body.issueSeq)) head = applyEvent(head, issue, event);
  return head;
}
module.exports = Object.freeze({validateIssueInput, validateResponseInput, validateDispositionInput,
  validateIssueBody, validateResponseBody, validateDispositionBody, validateHead, initialHead, applyEvent, projectIssue});
