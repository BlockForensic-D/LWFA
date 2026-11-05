'use strict';
// Raw profile output -> LWFA_COMPARISON_2 record. Raw output is never modified; this file only
// translates it into a shared vocabulary and keeps rawStatus, reason, subject and scope next to it.
// Normalization rules:
//  - an empty materialResults/toolResults list is never PASS; it is NOT_ASSESSED with the reason;
//  - NOT_OBTAINED and HASH_MISMATCH stay distinct codes;
//  - a dimension outside a profile is NOT_EVALUATED, an unreported one NOT_REPORTED;
//  - hard findings and advisories are separate lists; unknown T3 flags stop normalisation;
//  - a T3 creator/authority result of NOT_EVALUATED (prerequisite missing) is NOT_ASSESSED with the
//    raw reason, never a hard finding and never PASS;
//  - a presented disclosure that HB never reached (input rejected first) is NOT_ASSESSED, not NOT_PRESENTED (v2.1).
const path = require('node:path');
const SCHEMA = require(path.join(__dirname, '..', '..', 'config', 'schema_comparison_2.json'));
// Enums come from the schema file only (shared with gate.py).
const STATES = Object.keys(SCHEMA['x-states']);
const DIMENSIONS = SCHEMA['x-dimensions'];
const ADVISORY_FLAGS = SCHEMA['x-advisoryCodes'];
const UNRESOLVED = new Set(['OPEN', 'ANSWERED']); // disclosure.js UNRESOLVED
// Kit flags that restate a creator/authority status (disclosure.js pushes each flag iff that status);
// they are represented by those dimensions, and flag and status must agree in both directions.
const RESTATE_FLAGS = {ACTOR_CREATOR_MISMATCH: ['creatorIdentity', 'MISMATCH'], CREATOR_BINDING_INCOMPLETE: ['creatorIdentity', 'INCOMPLETE'],
  CREATOR_BINDING_NOT_EVALUATED: ['creatorIdentity', 'NOT_EVALUATED'], AUTHORITY_VIOLATION: ['authority', 'VIOLATIONS'],
  AUTHORITY_INCOMPLETE: ['authority', 'INCOMPLETE'], AUTHORITY_NOT_EVALUATED: ['authority', 'NOT_EVALUATED']};

const blobSubject = b => `${b.ownerVersionRef.objectID}/v${b.ownerVersionRef.version}/${b.slotID}`;
const procSubject = r => `${r.objectID}/v${r.version}`;
const sorted = a => [...new Set(a)].sort();

const dim = (state, extra = {}) => ({state, ...extra});
const NE = note => dim('NOT_EVALUATED', note ? {note} : {});

// Per-item integrity results -> dimension + findings. kind = 'MATERIAL' | 'TOOL'.
function items(results, kind, subjectOf, upstream) {
  if (!results || results.length === 0) return {d: dim('NOT_ASSESSED', {reason: upstream || 'NO_ITEMS_CHECKED', checked: 0}), f: []};
  const rows = results.map(r => ({subject: subjectOf(r), rawStatus: r.status}));
  for (const r of rows) if (!['HASH_MATCH', 'HASH_MISMATCH', 'NOT_OBTAINED'].includes(r.rawStatus)) throw new Error('NORMALIZE_UNKNOWN_ITEM_STATUS ' + r.rawStatus);
  const bad = rows.filter(r => r.rawStatus !== 'HASH_MATCH');
  const f = bad.map(r => ({code: `${kind}_${r.rawStatus === 'NOT_OBTAINED' ? 'NOT_OBTAINED' : 'HASH_MISMATCH'}`, rawReason: r.rawStatus, subjectRefs: [r.subject], missingRefs: []}));
  // Total order (subject, then rawStatus): duplicate subjects can never be ordered differently by two runtimes.
  const cmp = (x, y) => x < y ? -1 : x > y ? 1 : 0;
  rows.sort((a, b) => cmp(a.subject, b.subject) || cmp(a.rawStatus, b.rawStatus));
  return {d: dim(bad.length ? 'FAIL' : 'PASS', {checked: rows.length, items: rows}), f};
}

// T1/T2/T3 package verdict (core-shaped): binding MATCH|MISMATCH|NOT_ASSESSABLE.
function bindingOf(raw, scope) {
  if (raw.binding === 'MATCH') return {d: dim('PASS', {rawStatus: 'MATCH', scope}), f: []};
  if (raw.binding === 'MISMATCH') return {d: dim('FAIL', {rawStatus: 'MISMATCH', scope, reason: raw.reason}), f: [{code: 'BINDING_MISMATCH', rawReason: raw.reason}]};
  if (raw.binding === 'NOT_ASSESSABLE') return {d: dim('FAIL', {rawStatus: 'NOT_ASSESSABLE', scope, reason: raw.reason}), f: [{code: 'PACKAGE_INPUT_REJECTED', rawReason: raw.reason}]};
  throw new Error('NORMALIZE_UNKNOWN_BINDING ' + raw.binding);
}
function upstreamOf(pkg) {
  if (pkg.binding !== 'MATCH') return pkg.binding === 'MISMATCH' ? 'BINDING_FAILURE' : 'INPUT_REJECTED';
  if (pkg.context === 'UNSATISFIED') return 'CONTEXT_FAILURE';
  return null;
}

function fromT0(raw) {
  const D = {};
  const F = [];
  D.binding = dim(raw.manifestAnchored ? 'PASS' : 'FAIL', {rawStatus: raw.manifestAnchored ? 'ANCHORED' : 'NOT_ANCHORED', scope: 'MANIFEST_HASH_ANCHOR_ONLY'});
  if (!raw.manifestAnchored) F.push({dimension: 'binding', code: 'MANIFEST_NOT_ANCHORED', rawReason: 'NOT_ANCHORED'});
  D.basisContext = NE();
  const m = items(raw.materialResults, 'MATERIAL', r => blobSubject(r.blobRef));
  D.materialIntegrity = {...m.d, scope: 'MANIFEST_SUPPLIED_FILES_VS_LEDGER_HASHES'}; F.push(...m.f.map(x => ({dimension: 'materialIntegrity', ...x})));
  const t = items(raw.toolResults, 'TOOL', r => procSubject(r.processRef));
  D.toolIntegrity = {...t.d, scope: 'MANIFEST_TOOLS_VS_LEDGER_EXECUTABLE_DIGESTS'}; F.push(...t.f.map(x => ({dimension: 'toolIntegrity', ...x})));
  for (const k of ['creatorIdentity', 'disclosureCoverage', 'presentedDisclosure', 'presentedRecordsIntegrity', 'authority']) D[k] = NE();
  D.procedure = dim('NOT_RUN', {note: 'Profil ini tidak menjalankan prosedur forensik'});
  return {D, F, A: []};
}

function fromT1(raw) {
  const D = {}, F = [];
  const b = bindingOf(raw, 'MANIFEST_DIRECTED_LIFECYCLE_BINDING');
  D.binding = b.d; F.push(...b.f.map(x => ({dimension: 'binding', ...x})));
  D.basisContext = NE(`rawStatus ${raw.context}`);
  const m = items(raw.materialResults, 'MATERIAL', r => blobSubject(r.blobRef), upstreamOf({...raw, context: 'NOT_EVALUATED'}));
  D.materialIntegrity = {...m.d, scope: 'MANIFEST_DIRECTED_SUPPLIED_FILES'}; F.push(...m.f.map(x => ({dimension: 'materialIntegrity', ...x})));
  D.toolIntegrity = dim('NOT_REPORTED', {note: 'REF-LIFECYCLE v0.8.1: tool hilang (ENOENT) tidak dilaporkan; hash tool salah menjadi penolakan input pada binding'});
  for (const k of ['creatorIdentity', 'disclosureCoverage', 'presentedDisclosure', 'presentedRecordsIntegrity', 'authority']) D[k] = NE();
  D.procedure = dim('NOT_RUN', {note: 'Profil ini tidak menjalankan prosedur forensik'});
  return {D, F, A: []};
}

function corePackage(pkg, D, F) {
  const b = bindingOf(pkg, 'REQUEST_VERSION_MANIFEST_CHRONOLOGY_BASIS');
  D.binding = b.d; F.push(...b.f.map(x => ({dimension: 'binding', ...x})));
  if (pkg.context === 'SATISFIED') D.basisContext = dim('PASS', {rawStatus: 'SATISFIED', scope: 'LEDGER_DERIVED_BASIS_CONTEXT'});
  else if (pkg.context === 'UNSATISFIED') {
    const missing = sorted(pkg.contextFailure?.missing || []);
    D.basisContext = dim('FAIL', {rawStatus: 'UNSATISFIED', reason: pkg.reason, scope: 'LEDGER_DERIVED_BASIS_CONTEXT'});
    F.push({dimension: 'basisContext', code: 'CONTEXT_UNSATISFIED', rawReason: pkg.reason, missingRefs: missing,
      subjectRefs: sorted([...(pkg.contextFailure?.changed || []), ...(pkg.contextFailure?.unexpected || [])])});
  } else if (pkg.context === 'NOT_ASSESSABLE') D.basisContext = dim('NOT_ASSESSED', {rawStatus: 'NOT_ASSESSABLE', reason: upstreamOf(pkg)});
  else throw new Error('NORMALIZE_UNKNOWN_CONTEXT ' + pkg.context);
  const m = items(pkg.materialResults, 'MATERIAL', r => blobSubject(r.blobRef), upstreamOf(pkg));
  D.materialIntegrity = {...m.d, scope: 'LEDGER_DERIVED_REQUIRED_BLOBS'}; F.push(...m.f.map(x => ({dimension: 'materialIntegrity', ...x})));
  D.toolIntegrity = dim('NOT_REPORTED', {note: 'PCC v0.8.1: tidak ada hasil per tool; tool hilang (ENOENT) tidak dilaporkan, hash tool salah menjadi penolakan input pada binding (FIX-08A)'});
}

function fromT2(raw) {
  const D = {}, F = [];
  corePackage(raw, D, F);
  for (const k of ['creatorIdentity', 'disclosureCoverage', 'presentedDisclosure', 'presentedRecordsIntegrity', 'authority']) D[k] = NE();
  D.procedure = dim('NOT_RUN', {note: 'Profil ini tidak menjalankan prosedur forensik'});
  return {D, F, A: []};
}

// Subjects that triggered each advisory flag, recomputed from the reported lists only for
// attribution; the recomputed flag set must equal the kit's own flag set.
function advisorySubjects(d) {
  const post = d.postBasisIssues || [], lineage = d.predecessorIssues || [], prior = d.priorReviews || [];
  const ids = xs => sorted(xs.map(x => x.issueRef?.recordID).filter(Boolean));
  return {
    POST_BASIS_ISSUE_BEFORE_REQUEST: ids(post.filter(x => x.timing === 'AFTER_CHI_BEFORE_REQUEST')),
    UNRESOLVED_CHALLENGE_EXCLUDED_BY_CHI: ids(post.filter(x => x.timing === 'AFTER_CHI_BEFORE_REQUEST' && x.issueType === 'CHALLENGE' && UNRESOLVED.has(x.statusAtKappa))),
    POST_REQUEST_BASIS_ISSUE_UNLINKED: ids(post.filter(x => x.timing === 'AFTER_REQUEST_THROUGH_KAPPA' && !x.linkedToRequest)),
    UNRESOLVED_PREDECESSOR_CHALLENGE: ids(lineage.filter(x => x.unresolvedChallenge && x.explicitPredecessor && !x.inCurrentBasis)),
    UNRESOLVED_EARLIER_VERSION_CHALLENGE: ids(lineage.filter(x => x.unresolvedChallenge && !x.explicitPredecessor && !x.inCurrentBasis)),
    UNRESOLVED_PRIOR_REVIEW_CHALLENGE: ids(prior.flatMap(r => r.issues.filter(i => i.issueType === 'CHALLENGE' && UNRESOLVED.has(i.statusAtKappa))))
  };
}

function fromT3(raw) {
  const D = {}, F = [], A = [];
  corePackage(raw.packageAssessment, D, F);
  const d = raw.disclosure, pd = raw.presentedDisclosureCheck;
  const cb = d.creatorBinding;
  const cbMap = {BOUND: 'PASS', MISMATCH: 'FAIL', INCOMPLETE: 'FAIL', NOT_EVALUATED: 'NOT_ASSESSED'};
  if (!(cb.status in cbMap)) throw new Error('NORMALIZE_UNKNOWN_CREATOR ' + cb.status);
  if (cb.status === 'NOT_EVALUATED') // prerequisite missing (no block-derived identities): not a verdict
    D.creatorIdentity = dim('NOT_ASSESSED', {rawStatus: cb.status, reason: cb.reason || 'CREATOR_BINDING_NOT_EVALUATED', scope: 'DISCLOSURE_REQUIRED_RECORDS', checked: (cb.records || []).length});
  else D.creatorIdentity = dim(cbMap[cb.status], {rawStatus: cb.status, scope: 'DISCLOSURE_REQUIRED_RECORDS', checked: (cb.records || []).length});
  if (cb.status === 'MISMATCH' || cb.status === 'INCOMPLETE') F.push({dimension: 'creatorIdentity', code: cb.status === 'MISMATCH' ? 'CREATOR_MISMATCH' : 'CREATOR_BINDING_' + cb.status, rawReason: cb.status,
    subjectRefs: sorted((cb.records || []).filter(r => r.status && r.status !== 'BOUND').map(r => r.recordID))});
  D.disclosureCoverage = dim(d.coverage.status === 'SATISFIED' ? 'PASS' : 'FAIL', {rawStatus: d.coverage.status, scope: 'EXTERNAL_DISCLOSURE_V2_REQUIRED_RECORDS', checked: d.coverage.requiredRecordCount});
  if (d.coverage.status !== 'SATISFIED') F.push({dimension: 'disclosureCoverage', code: 'DISCLOSURE_COVERAGE_' + d.coverage.status, rawReason: d.coverage.status});
  if (pd.status === 'NOT_PRESENTED') { D.presentedDisclosure = dim('NOT_PRESENTED', {rawStatus: 'NOT_PRESENTED'}); D.presentedRecordsIntegrity = dim('NOT_PRESENTED', {rawStatus: 'NOT_PRESENTED'}); }
  else if (pd.coverageStatus === 'SATISFIED' || pd.coverageStatus === 'UNSATISFIED') {
    const ok = pd.coverageStatus === 'SATISFIED';
    D.presentedDisclosure = dim(ok ? 'PASS' : 'FAIL', {rawStatus: pd.coverageStatus, reason: (pd.reasonPaths || []).join('|'), scope: 'PRESENTED_VS_RECOMPUTED_DISCLOSURE'});
    if (!ok) F.push({dimension: 'presentedDisclosure', code: 'PRESENTED_DISCLOSURE_INCOMPLETE', rawReason: (pd.reasonPaths || []).join('|'),
      missingRefs: sorted(pd.missingRecordIDs || []), subjectRefs: sorted([...(pd.unexpectedRecordIDs || []).map(String), ...(pd.changedRecordIDs || [])])});
    const changed = pd.changedRecordIDs || [];
    D.presentedRecordsIntegrity = dim(changed.length ? 'FAIL' : 'PASS', {rawStatus: changed.length ? 'CHANGED' : 'UNCHANGED', scope: 'PRESENTED_RECORDS_IN_RECOMPUTED_SET'});
    if (changed.length) F.push({dimension: 'presentedRecordsIntegrity', code: 'PRESENTED_RECORD_CHANGED', rawReason: 'changedRecordIDs', subjectRefs: sorted(changed)});
  } else throw new Error('NORMALIZE_UNKNOWN_PRESENTED ' + JSON.stringify(pd.status || pd.coverageStatus));
  const au = d.authority, auMap = {CONSISTENT: 'PASS', VIOLATIONS: 'FAIL', INCOMPLETE: 'FAIL', NOT_EVALUATED: 'NOT_ASSESSED'};
  if (!(au.status in auMap)) throw new Error('NORMALIZE_UNKNOWN_AUTHORITY ' + au.status);
  if (au.status === 'NOT_EVALUATED') // no identities supplied: replay of authority rules not possible, not a verdict
    D.authority = dim('NOT_ASSESSED', {rawStatus: au.status, reason: au.roleEvidence || 'AUTHORITY_NOT_EVALUATED', scope: 'SCOPED_RECORDS', checked: au.checkedRecords});
  else D.authority = dim(auMap[au.status], {rawStatus: au.status, scope: 'SCOPED_RECORDS', checked: au.checkedRecords});
  if (au.status === 'VIOLATIONS' || au.status === 'INCOMPLETE') F.push({dimension: 'authority', code: au.status === 'VIOLATIONS' ? 'AUTHORITY_VIOLATION' : 'AUTHORITY_' + au.status, rawReason: au.status,
    subjectRefs: sorted([...(au.violations || []), ...(au.incomplete || [])].map(v => v.recordID || v.recordRef?.recordID).filter(Boolean))});
  D.procedure = dim('NOT_RUN', {rawStatus: raw.procedure?.status});
  if (raw.procedure?.status !== 'NOT_RUN') throw new Error('NORMALIZE_UNEXPECTED_PROCEDURE ' + raw.procedure?.status);
  // Flags: restating ones must agree with the status of the dimension they restate (both directions);
  // advisory ones become advisories.
  const subjects = advisorySubjects(d);
  for (const flag of d.flags) {
    if (RESTATE_FLAGS[flag]) { const [k, st] = RESTATE_FLAGS[flag]; if (D[k].rawStatus !== st) throw new Error(`NORMALIZE_FLAG_STATUS_DISAGREE ${flag} ${D[k].rawStatus}`); continue; }
    if (!ADVISORY_FLAGS.includes(flag)) throw new Error('NORMALIZE_UNKNOWN_FLAG ' + flag);
    A.push({code: flag, subjectRefs: subjects[flag]});
  }
  for (const [flag, [k, st]] of Object.entries(RESTATE_FLAGS)) if (D[k].rawStatus === st && !d.flags.includes(flag)) throw new Error(`NORMALIZE_FLAG_MISSING ${flag}`);
  const recomputed = ADVISORY_FLAGS.filter(f => subjects[f].length > 0).sort();
  const reported = d.flags.filter(f => ADVISORY_FLAGS.includes(f)).sort();
  if (recomputed.join() !== reported.join()) throw new Error(`NORMALIZE_ADVISORY_ATTRIBUTION_MISMATCH reported=${reported} recomputed=${recomputed}`);
  return {D, F, A};
}

function fromHB(raw, presented) {
  const D = {}, F = [];
  if (raw.format !== 'HASH_COC_REFERENCE_1') throw new Error('NORMALIZE_UNKNOWN_HB_FORMAT ' + raw.format);
  const rejectedBy = raw.input === 'REJECTED' ? (raw.creatorBinding === 'MISMATCH' ? 'CREATOR_FAILURE' : raw.binding === 'MISMATCH' ? 'BINDING_FAILURE' : 'INPUT_REJECTED') : null;
  // binding
  if (raw.binding === 'MATCH') D.binding = dim('PASS', {rawStatus: 'MATCH', scope: 'REQUEST_VERSION_MANIFEST_CHRONOLOGY_BASIS_PRESENTED'});
  else if (raw.binding === 'MISMATCH') { D.binding = dim('FAIL', {rawStatus: 'MISMATCH', reason: raw.reason}); F.push({dimension: 'binding', code: 'BINDING_MISMATCH', rawReason: raw.reason}); }
  else if (raw.binding === 'NOT_ASSESSABLE') {
    if (rejectedBy === 'CREATOR_FAILURE') D.binding = dim('NOT_ASSESSED', {rawStatus: 'NOT_ASSESSABLE', reason: rejectedBy});
    else if (rejectedBy === 'INPUT_REJECTED') { D.binding = dim('FAIL', {rawStatus: 'NOT_ASSESSABLE', reason: raw.reason}); F.push({dimension: 'binding', code: 'PACKAGE_INPUT_REJECTED', rawReason: raw.reason}); }
    else throw new Error('NORMALIZE_HB_BINDING_STATE');
  } else throw new Error('NORMALIZE_UNKNOWN_BINDING ' + raw.binding);
  D.basisContext = NE(`obligations.basisContextCompleteness ${raw.obligations.basisContextCompleteness}`);
  // creator identity over every case record in the snapshot
  if (raw.creatorBinding === 'BOUND') D.creatorIdentity = dim('PASS', {rawStatus: 'BOUND', scope: 'ALL_CASE_RECORDS_IN_SNAPSHOT', checked: raw.registrationTrail.length});
  else if (raw.creatorBinding === 'MISMATCH') { D.creatorIdentity = dim('FAIL', {rawStatus: 'MISMATCH', reason: raw.reason, scope: 'ALL_CASE_RECORDS_IN_SNAPSHOT'}); F.push({dimension: 'creatorIdentity', code: 'CREATOR_MISMATCH', rawReason: raw.reason}); }
  else D.creatorIdentity = dim('NOT_ASSESSED', {rawStatus: raw.creatorBinding, reason: rejectedBy || 'NOT_ASSESSABLE'});
  const up = raw.input === 'VALID' ? null : rejectedBy;
  const m = items(raw.materialResults, 'MATERIAL', r => blobSubject(r.blobRef), up);
  D.materialIntegrity = {...m.d, scope: 'MANIFEST_SUPPLIED_FILES_OF_SUPPLIED_MATERIALS'}; F.push(...m.f.map(x => ({dimension: 'materialIntegrity', ...x})));
  const t = items(raw.toolResults, 'TOOL', r => procSubject(r.processRef), up);
  D.toolIntegrity = {...t.d, scope: 'MANIFEST_TOOLS_BOUND_TO_CHECKPLAN'}; F.push(...t.f.map(x => ({dimension: 'toolIntegrity', ...x})));
  D.disclosureCoverage = NE(`obligations.presentedHistoryCompleteness ${raw.obligations.presentedHistoryCompleteness}`);
  D.presentedDisclosure = NE('HB tidak menilai kelengkapan disclosure');
  // HB leaves its default 'NOT_PRESENTED' when it rejects the input before reaching a presented disclosure;
  // only the call context (presented) can tell "not presented" from "presented but not assessed".
  if (raw.presentedRecordsIntegrity === 'MATCH') D.presentedRecordsIntegrity = dim('PASS', {rawStatus: 'MATCH', scope: 'PRESENTED_RECORDS_COMMITMENT_AND_POSITION'});
  else if (raw.presentedRecordsIntegrity === 'NOT_PRESENTED' && !presented) D.presentedRecordsIntegrity = dim('NOT_PRESENTED', {rawStatus: 'NOT_PRESENTED'});
  else if (raw.presentedRecordsIntegrity === 'NOT_PRESENTED' && rejectedBy) D.presentedRecordsIntegrity = dim('NOT_ASSESSED', {rawStatus: 'NOT_PRESENTED', reason: rejectedBy});
  else throw new Error(`NORMALIZE_HB_PRESENTED_STATE ${raw.presentedRecordsIntegrity} presented=${presented}`);
  D.authority = NE(`obligations.scopedAuthority ${raw.obligations.scopedAuthority}`);
  D.procedure = dim('NOT_RUN', {rawStatus: raw.obligations.forensicProcedure});
  return {D, F, A: []};
}

const BY = {T0: fromT0, T1: fromT1, HB: fromHB, T2: fromT2, T3: fromT3};

// presented: whether a presented disclosure was passed to the call (registry presentedDisclosurePath).
function normalize({runID, rowID, checker, checkerVersion, raw, error, rawOutputRef, rawOutputSHA256, presented}) {
  if (typeof presented !== 'boolean') throw new Error('NORMALIZE_PRESENTED_FLAG_REQUIRED');
  const base = {schema: 'LWFA_COMPARISON_2', runID, rowID, checker, checkerVersion};
  if (error) {
    const dimensions = Object.fromEntries(DIMENSIONS.map(k => [k, dim('OPERATIONAL_ERROR')]));
    return {...base, execution: 'OPERATIONAL_ERROR', error, dimensions, hardFindings: [], advisories: [],
      hardDetected: false, advisoryPresent: false, anyFinding: false, rawOutputRef, rawOutputSHA256};
  }
  const {D, F, A} = BY[checker](raw, presented);
  const dimensions = Object.fromEntries(DIMENSIONS.map(k => { if (!D[k] || !STATES.includes(D[k].state)) throw new Error(`NORMALIZE_DIMENSION ${checker} ${k}`); return [k, D[k]]; }));
  const hardFindings = F.map(f => ({dimension: f.dimension, code: f.code, rawReason: f.rawReason ?? null,
    subjectRefs: f.subjectRefs || [], missingRefs: f.missingRefs || [], sourcePath: rawOutputRef}));
  for (const f of hardFindings) if (dimensions[f.dimension].state !== 'FAIL') throw new Error(`NORMALIZE_FINDING_WITHOUT_FAIL ${checker} ${f.dimension}`);
  for (const [k, v] of Object.entries(dimensions)) if (v.state === 'FAIL' && !hardFindings.some(f => f.dimension === k)) throw new Error(`NORMALIZE_FAIL_WITHOUT_FINDING ${checker} ${k}`);
  const advisories = A.map(a => ({code: a.code, subjectRefs: a.subjectRefs, sourcePath: rawOutputRef}));
  return {...base, execution: 'COMPLETED', dimensions, hardFindings, advisories,
    hardDetected: hardFindings.length > 0, advisoryPresent: advisories.length > 0, anyFinding: hardFindings.length + advisories.length > 0,
    rawOutputRef, rawOutputSHA256};
}

// Exact outcome signature used by expected_outcomes.json and the gate: dimension states,
// hard findings (dimension|code|rawReason|subjects|missing) and advisories (code|subjects).
function outcomeOf(rec) {
  return {
    execution: rec.execution,
    dimensions: Object.fromEntries(DIMENSIONS.map(k => [k, rec.dimensions[k].state])),
    hardFindings: rec.hardFindings.map(f => [f.dimension, f.code, f.rawReason ?? '', f.subjectRefs.join('+'), f.missingRefs.join('+')].join('|')).sort(),
    advisories: rec.advisories.map(a => [a.code, a.subjectRefs.join('+')].join('|')).sort()
  };
}

module.exports = {STATES, DIMENSIONS, ADVISORY_FLAGS, RESTATE_FLAGS, normalize, outcomeOf, advisorySubjects};
