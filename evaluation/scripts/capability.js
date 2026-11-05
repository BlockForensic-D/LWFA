'use strict';
// Offline capability evaluation of 37 fixed assessment rows across five verification profiles.
// Outputs include raw assessments, LWFA_COMPARISON_2 records, profile tables, class summaries,
// diagnostic cumulative unions, requirement checks, T3 reproduction receipts, and legacy exports.
// The complete experimental harness checks exact expected outcomes separately through gate.py.
// Usage: node capability.js --kit KIT --hc HC --camp CAMPAIGN --out RUN_DIR --run-id RUN_ID
const fs = require('node:fs'), path = require('node:path');
const C = require('./lib/common'), kit = require('./lib/kit'), Prof = require('./lib/profiles');
const {normalize, DIMENSIONS} = require('./lib/normalize'), {evaluate} = require('./lib/assertions');

const arg = (() => { const a = process.argv.slice(2), o = {}; for (let i = 0; i < a.length; i += 2) o[a[i].replace(/^--/, '')] = a[i + 1]; return o; })();
for (const k of ['kit', 'hc', 'camp', 'out', 'run-id']) if (!arg[k]) throw new Error('MISSING_ARG --' + k);
const KIT = path.resolve(arg.kit), HC = path.resolve(arg.hc), CAMP = path.resolve(arg.camp), OUT = path.resolve(arg.out), runID = arg['run-id'];
const CFG = path.join(C.HERE, 'config');
const profiles = C.readJson(path.join(CFG, 'profiles.json'));
const reg = C.loadRegistry(path.join(CFG, 'rows.json'), profiles);
if (profiles.profiles.map(p => p.id).join() !== Prof.PROFILE_IDS.join()) throw new Error('PROFILES_CONFIG_MISMATCH');
const reqDoc = C.readJson(path.join(CFG, 'requirements.json'));
const lock = C.readJson(path.join(OUT, 'source-lock.json'));
if (lock.runID !== runID || lock.status !== 'PASS') throw new Error('SOURCE_LOCK_NOT_PASSED_FOR_THIS_RUN');
const version = {T0: `harness-SHA256SUMS:${lock.harness.sha256sumsSHA256}`, T1: `kit-RELEASE_SHA256:${lock.kit.releaseManifestSHA256}`,
  HB: `hashcoc-release-files:${lock.hashcoc.releaseFilesSHA256}`, T2: `kit-RELEASE_SHA256:${lock.kit.releaseManifestSHA256}`,
  T3: `kit-RELEASE_SHA256:${lock.kit.releaseManifestSHA256}`};

const CAP = path.join(OUT, 'capability');
fs.mkdirSync(CAP); // fails if a previous capability directory exists
const K = kit.load(KIT, HC), net = kit.network(CAMP);

// 1. Snapshot replay and registry-reference validation before profile evaluation.
const snaps = new Map(), refProblems = [];
for (const row of reg.rows) {
  const key = row.snapshotPath + '|' + row.requestRef.caseID;
  if (!snaps.has(key)) snaps.set(key, kit.readSnapshot(K, CAMP, net, row.snapshotPath, row.requestRef.caseID));
  const s = snaps.get(key).snapshot, caseDir = path.join(CAMP, 'cases', row.scenario);
  const req = s.records.get(row.requestRef.recordID), pkg = s.records.get(row.packageRecordID);
  if (!req || req.kind !== 'REVIEW_REQUEST' || C.canon(K.m.recordRef(req)) !== C.canon(row.requestRef)) refProblems.push(row.rowID + ': REGISTRY_REQUEST_REF');
  if (!pkg || pkg.kind !== 'PACKAGE_RECORD' || C.canon(K.m.recordRef(pkg)) !== C.canon(row.packageRecordRef)) refProblems.push(row.rowID + ': REGISTRY_PACKAGE_REF');
  if (req && pkg && (req.caseID !== row.requestRef.caseID || pkg.caseID !== row.requestRef.caseID)) refProblems.push(row.rowID + ': REGISTRY_CASE');
  if (!fs.existsSync(path.join(caseDir, row.packageRelativePath, 'manifest.json'))) refProblems.push(row.rowID + ': REGISTRY_PACKAGE_DIR');
  if (row.presentedDisclosurePath && !fs.existsSync(path.join(caseDir, row.presentedDisclosurePath))) refProblems.push(row.rowID + ': REGISTRY_PRESENTED_FILE');
  if (!fs.existsSync(path.join(CAMP, row.archivedAssessmentPath))) refProblems.push(row.rowID + ': REGISTRY_ARCHIVED_ASSESSMENT');
}
if (refProblems.length) { console.error('STOP: registry references do not match the campaign\n' + refProblems.join('\n')); process.exit(1); }

// 2. Five-profile evaluation, raw-output retention, and normalization for each row.
const records = [], rawT3 = new Map(), rawAll = new Map(), perRow = [], diffs = [];
const snapOf = row => snaps.get(row.snapshotPath + '|' + row.requestRef.caseID);
for (const row of reg.rows) {
  const S = snapOf(row), calls = Prof.calls(K, CAMP, row, S), raws = {};
  for (const P of Prof.PROFILE_IDS) {
    let raw, error = null;
    try { raw = calls[P](); } catch (e) { error = {name: e.name, code: e.code || null, message: e.message}; }
    const rel = `capability/raw/${C.rowKey(row.rowID)}/${P}.json`;
    const env = {format: 'LWFA_RAW_OUTPUT_2', runID, rowID: row.rowID, checker: P, checkerVersion: version[P],
      serialization: 'CANON_VALUE_1: object keys sorted; Map -> {$map}, Buffer -> {$bytes:{sha256,length}}, BigInt -> {$bigint}; field values otherwise unchanged',
      execution: error ? 'OPERATIONAL_ERROR' : 'COMPLETED', error, output: error ? null : C.canonValue(raw)};
    const bytes = JSON.stringify(env, null, 1) + '\n';
    C.writeNew(path.join(OUT, rel), bytes);
    raws[P] = raw;
    records.push(normalize({runID, rowID: row.rowID, checker: P, checkerVersion: version[P], raw, error, rawOutputRef: rel, rawOutputSHA256: C.sha(Buffer.from(bytes)),
      presented: row.presentedDisclosurePath !== null}));
  }
  rawAll.set(row.rowID, raws);
  if (raws.T3 !== undefined) rawT3.set(row.rowID, raws.T3);
  const archived = C.readJson(path.join(CAMP, row.archivedAssessmentPath));
  const got = raws.T3 === undefined ? null : K.m.canonicalJson(raws.T3), want = K.m.canonicalJson(archived);
  const identical = got === want;
  if (!identical) diffs.push({rowID: row.rowID, keys: raws.T3 === undefined ? ['<operational error>'] : Object.keys(archived).filter(k => K.m.canonicalJson(archived[k] ?? null) !== K.m.canonicalJson(raws.T3[k] ?? null))});
  perRow.push({rowID: row.rowID, t3CanonicalSHA256: got === null ? null : C.sha(Buffer.from(got)), archivedCanonicalSHA256: C.sha(Buffer.from(want)), identical});
}

// 3. Evaluation of kit v0.8.1 requirement assertions against raw T3 output.
const reqResults = evaluate(reqDoc, rawT3);

// 4. Outputs.
const W = (rel, data) => C.writeNew(path.join(CAP, rel), data);
const WJ = (rel, v) => W(rel, JSON.stringify(v, null, 1) + '\n');
W('normalized.jsonl', records.map(r => JSON.stringify(r)).join('\n') + '\n');
WJ('replay_diffs.json', diffs);
// v2.1: byte copies of the 37 archived assessments, so the gate can bind archivedCanonicalSHA256 to the pinned campaign.
fs.mkdirSync(path.join(CAP, 'archived'));
for (const row of reg.rows) fs.copyFileSync(path.join(CAMP, row.archivedAssessmentPath), path.join(CAP, 'archived', C.rowKey(row.rowID) + '.json'), fs.constants.COPYFILE_EXCL);
WJ('replay_receipt.json', {format: 'LWFA_REPLAY_RECEIPT_2', runID, rows: reg.rows.length, reproduced: perRow.filter(r => r.identical).length,
  comparison: 'kit m.canonicalJson(T3 raw) === m.canonicalJson(archived assessment)', archivedCopies: 'archived/<rowKey>.json (byte copies of the pinned campaign files)', perRow,
  snapshots: [...snaps.values()].map(s => ({snapshotPath: s.snapshotPath, caseID: s.caseID, blockCount: s.blockCount, checkpoint: s.cp,
    replaySignature: C.canonSha(kit.projectReplay(K, s))})).sort((a, b) => a.snapshotPath < b.snapshotPath ? -1 : 1),
  trust: 'Captured Org3 checkpoint and peer validation metadata are trusted; raw block hashes, order, record commitments and actor bindings are recomputed offline. No fresh peer connection.'});
WJ('requirements_check.json', {format: 'LWFA_REQUIREMENTS_CHECK_1', runID, requirementsSHA256: C.shaFile(path.join(CFG, 'requirements.json')),
  total: reqResults.length, passed: reqResults.filter(r => r.status === 'PASS').length, failed: reqResults.filter(r => r.status !== 'PASS').length, results: reqResults});

const byKey = new Map(records.map(r => [r.rowID + '|' + r.checker, r]));
const codes = r => r.hardFindings.map(f => `${f.dimension}:${f.code}${f.rawReason ? '(' + f.rawReason + ')' : ''}${f.missingRefs.length ? '[missing ' + f.missingRefs.join('+') + ']' : ''}${f.subjectRefs.length ? '[' + f.subjectRefs.join('+') + ']' : ''}`).join(' ; ');
const table = reg.rows.map(row => {
  const g = P => byKey.get(row.rowID + '|' + P);
  const o = {rowID: row.rowID, scenario: row.scenario, assessment: row.assessment, kind: row.kind, defectClass: row.defectClass};
  for (const P of ['HB', 'T2', 'T3']) o[P + '_hard'] = g(P).hardDetected ? 1 : 0;
  o.T3_advisory = g('T3').advisoryPresent ? 1 : 0; o.T3_any = g('T3').anyFinding ? 1 : 0;
  for (const P of ['T0', 'T1']) o[P + '_hard'] = g(P).hardDetected ? 1 : 0;
  for (const P of ['HB', 'T2', 'T3', 'T0', 'T1']) o[P + '_findings'] = codes(g(P));
  o.T3_advisories = g('T3').advisories.map(a => `${a.code}[${a.subjectRefs.join('+')}]`).join(' ; ');
  o.operationalErrors = Prof.PROFILE_IDS.filter(P => g(P).execution !== 'COMPLETED').join('|');
  return o;
});
W('profile_table.csv', C.toCsv(table));
W('dimension_states.csv', C.toCsv(records.flatMap(r => DIMENSIONS.map(d => ({rowID: r.rowID, checker: r.checker, dimension: d,
  state: r.dimensions[d].state, rawStatus: r.dimensions[d].rawStatus ?? '', reason: r.dimensions[d].reason ?? '', scope: r.dimensions[d].scope ?? '',
  checked: r.dimensions[d].checked ?? '', note: r.dimensions[d].note ?? ''})))));

const classes = {};
for (const cls of C.CLASSES) {
  const rows = reg.rows.filter(r => r.defectClass === cls);
  const n = f => rows.filter(f).length;
  classes[cls] = {n: rows.length,
    hard: Object.fromEntries(Prof.PROFILE_IDS.map(P => [P, n(r => byKey.get(r.rowID + '|' + P).hardDetected)])),
    advisory: {T3: n(r => byKey.get(r.rowID + '|T3').advisoryPresent)},
    any: {T3: n(r => byKey.get(r.rowID + '|T3').anyFinding)},
    operationalErrors: n(r => Prof.PROFILE_IDS.some(P => byKey.get(r.rowID + '|' + P).execution !== 'COMPLETED'))};
}
WJ('class_summary.json', {format: 'LWFA_CLASS_SUMMARY_2', runID, rows: reg.rows.length,
  definitions: {hard: 'jumlah baris dengan >=1 hard finding (hardDetected) pada profil itu', advisory: 'jumlah baris T3 dengan >=1 advisory',
    any: 'hard OR advisory (bukan accepted/rejected evidence)', unit: 'baris asesmen; bukan insiden independen; bukan akurasi'},
  classes,
  controlsWithAdvisory: reg.rows.filter(r => r.defectClass === 'CONTROL' && byKey.get(r.rowID + '|T3').advisoryPresent)
    .map(r => ({rowID: r.rowID, advisories: byKey.get(r.rowID + '|T3').advisories.map(a => a.code), interpretation: 'Advisory yang diharapkan pada kontrol; bukan false positive otomatis'})),
  notEvaluatedIsNotAcceptance: 'NOT_EVALUATED, NOT_REPORTED, NOT_ASSESSED tidak sama dengan diterima.'});

// cumulative_union: OR over profiles in a fixed order. Monotone by construction; diagnostic only.
const ORDER = [['T0', 'hard'], ['T1', 'hard'], ['HB', 'hard'], ['T2', 'hard'], ['T3', 'hard'], ['T3', 'any']];
const flag = (r, [P, k]) => k === 'any' ? byKey.get(r.rowID + '|' + P).anyFinding : byKey.get(r.rowID + '|' + P).hardDetected;
WJ('cumulative_union.json', {format: 'LWFA_CUMULATIVE_UNION_1', runID,
  label: 'gabungan diagnostik kumulatif (cumulative_union)',
  warning: 'Bukan profil tunggal dan bukan ladder kewajiban. Nilainya tidak menurun karena konstruksi OR. Biaya panggilan T3 bukan biaya gabungan ini; gabungan yang dieksekusi adalah profil baru yang harus diukur sendiri.',
  order: ORDER.map(([P, k]) => P + '_' + k),
  classes: Object.fromEntries(C.CLASSES.map(cls => { const rows = reg.rows.filter(r => r.defectClass === cls);
    return [cls, {n: rows.length, union: ORDER.map((_, i) => rows.filter(r => ORDER.slice(0, i + 1).some(o => flag(r, o))).length)}]; }))});
fs.copyFileSync(path.join(CFG, 'obligation_matrix.csv'), path.join(CAP, 'obligation_matrix.csv'), fs.constants.COPYFILE_EXCL);

// 5. Legacy compatibility exports (same column logic as the ladder package scripts; timing columns omitted).
const st = rs => rs || [];
const e1 = [], hb = [];
for (const row of reg.rows) {
  const r = rawAll.get(row.rowID), S = snapOf(row), rec = perRow.find(x => x.rowID === row.rowID);
  if (Prof.PROFILE_IDS.some(P => r[P] === undefined)) continue; // operational errors already recorded
  const bad = xs => st(xs).filter(x => x.status !== 'HASH_MATCH');
  const t0bad = [...r.T0.materialResults, ...r.T0.toolResults].map(x => x.status);
  const T0 = !r.T0.manifestAnchored || t0bad.some(s => s !== 'HASH_MATCH');
  const mm = xs => ({mismatch: st(xs).filter(x => x.status === 'HASH_MISMATCH').length, notObtained: st(xs).filter(x => x.status === 'NOT_OBTAINED').length});
  const m1 = mm(r.T1.materialResults), m2 = mm(r.T2.materialResults);
  const T1 = r.T1.binding !== 'MATCH' || m1.mismatch + m1.notObtained > 0;
  const T2 = r.T2.binding !== 'MATCH' || r.T2.context !== 'SATISFIED' || m2.mismatch + m2.notObtained > 0;
  const d = r.T3.disclosure, pd = r.T3.presentedDisclosureCheck;
  const T3h = T2 || d.coverage.status !== 'SATISFIED' || d.creatorBinding.status !== 'BOUND' || d.authority.status !== 'CONSISTENT' || pd.coverageStatus === 'UNSATISFIED';
  const T3 = T3h || d.flags.length > 0;
  e1.push({scenario: row.scenario, assessment: row.assessment, kind: row.kind, blocks: S.blockCount,
    T0: +T0, T0_detail: T0 ? `anchored=${r.T0.manifestAnchored};mismatch=${t0bad.filter(s => s === 'HASH_MISMATCH').length};notObtained=${t0bad.filter(s => s === 'NOT_OBTAINED').length}` : '',
    T1: +T1, T1_detail: r.T1.binding !== 'MATCH' ? `${r.T1.binding}:${r.T1.reason}` : (T1 ? `materials mismatch=${m1.mismatch} notObtained=${m1.notObtained}` : `context=${r.T1.context}`),
    T2: +T2, T2_detail: r.T2.binding !== 'MATCH' ? `${r.T2.binding}:${r.T2.reason}` : r.T2.context !== 'SATISFIED' ? `${r.T2.context}:${r.T2.reason}:${(r.T2.contextFailure?.missing || []).join('+')}` : (T2 ? `materials mismatch=${m2.mismatch} notObtained=${m2.notObtained}` : ''),
    T3: +T3, T3_hard: +T3h, T3_flags: d.flags.join('|'), presented: pd.coverageStatus || pd.status, presentedMissing: (pd.missingRecordIDs || []).join('|'),
    requiredRecords: d.requiredRecords.length, firstTier: T0 ? 'T0' : T1 ? 'T1' : T2 ? 'T2' : T3 ? 'T3' : 'NONE', T3_reproduces_archive: rec.identical ? 1 : 0});
  const b = r.HB, bb = [...bad(b.materialResults), ...bad(b.toolResults)];
  hb.push({scenario: row.scenario, assessment: row.assessment, kind: row.kind, T0: +T0, T1: +T1, B: +(b.input !== 'VALID' || bb.length > 0), T2: +T2, T3_hard: +T3h, T3: +T3,
    B_input: b.input, B_binding: b.binding, B_creator: b.creatorBinding, B_reason: b.reason || '', B_notMatch: bb.map(x => x.status).join('|'),
    B_presentedIntegrity: b.presentedRecordsIntegrity, B_trail: b.registrationTrail.length, S_records: S.snapshot.records.size});
}
W('compat/rq2_tier_ablation_offline_replay.csv', C.toCsv(e1));
W('compat/hashcoc_vs_tiers.csv', C.toCsv(hb));
const LEG = path.join(C.HERE, 'reference', 'legacy_ladder');
const cmpCsv = (name, ours) => {
  const ref = C.parseCsv(fs.readFileSync(path.join(LEG, name), 'utf8'));
  const keyOf = x => x.scenario + '/' + x.assessment, drop = x => Object.fromEntries(Object.entries(x).filter(([k]) => !k.startsWith('ms_')).map(([k, v]) => [k, String(v)]));
  const A = new Map(ref.map(x => [keyOf(x), drop(x)])), B = new Map(ours.map(x => [keyOf(x), drop(x)]));
  const problems = [];
  if (A.size !== ref.length || B.size !== ours.length) problems.push('DUPLICATE_KEYS');
  for (const k of new Set([...A.keys(), ...B.keys()])) {
    if (!A.has(k) || !B.has(k)) { problems.push(`${k}: only in ${A.has(k) ? 'legacy' : 'new'}`); continue; }
    const cols = new Set([...Object.keys(A.get(k)), ...Object.keys(B.get(k))]);
    for (const c of cols) if (A.get(k)[c] !== B.get(k)[c]) problems.push(`${k}.${c}: legacy=${A.get(k)[c]} new=${B.get(k)[c]}`);
  }
  return {file: name, legacySHA256: C.shaFile(path.join(LEG, name)), rows: ours.length, comparedWithout: 'ms_* timing columns', status: problems.length ? 'FAIL' : 'PASS', problems};
};
WJ('compat/compat_check.json', {format: 'LWFA_COMPAT_CHECK_1', runID, checks: [cmpCsv('rq2_tier_ablation_offline_replay.csv', e1), cmpCsv('hashcoc_vs_tiers.csv', hb)]});

// 6. HB and T3 comparison against the frozen 24-pair HashCoC v010 results.
const frozenPath = path.join(HC, 'results/offline-20261005/comparison.csv');
const frozen = C.parseCsv(fs.readFileSync(frozenPath, 'utf8'));
const status = rs => rs?.length ? rs.map(x => x.status).join('|') : 'NOT_ASSESSED';
const pairProblems = [];
for (const f of frozen) {
  const rowID = f.id.replace('__', '/'), r = rawAll.get(rowID);
  if (!r) { pairProblems.push(rowID + ': not in registry'); continue; }
  const b = r.HB, p = r.T3, pa = p.packageAssessment, pc = p.presentedDisclosureCheck;
  const ours = {baseline_binding: b.binding, baseline_blob_statuses: status(b.materialResults), baseline_creator: b.creatorBinding,
    baseline_context: b.obligations.basisContextCompleteness, baseline_history: b.obligations.presentedHistoryCompleteness,
    pcc_binding: pa.binding, pcc_context: pa.context, pcc_blob_statuses: status(pa.materialResults), pcc_flags: p.disclosure.flags.join('|'),
    pcc_presented_coverage: pc.coverageStatus || pc.status, pcc_missing_record_ids: [...(pa.contextFailure?.missing || []), ...(pc.missingRecordIDs || [])].join('|')};
  for (const [k, v] of Object.entries(ours)) if (String(v) !== f[k]) pairProblems.push(`${rowID}.${k}: frozen=${f[k]} new=${v}`);
}
WJ('hb_vs_frozen_comparison.json', {format: 'LWFA_HB_FROZEN_AGREEMENT_1', runID, frozenFile: 'HASHCOC/results/offline-20261005/comparison.csv',
  frozenSHA256: C.shaFile(frozenPath), pairs: frozen.length, status: pairProblems.length ? 'FAIL' : 'PASS', problems: pairProblems,
  frozenCopy: 'hb_frozen_reference.csv (byte copy, for the gate\'s independent re-derivation)'});
// v2.1: byte copy of the frozen file so the gate can re-derive the 24-pair agreement from this run's raw output.
fs.copyFileSync(frozenPath, path.join(CAP, 'hb_frozen_reference.csv'), fs.constants.COPYFILE_EXCL);

const opErr = records.filter(r => r.execution !== 'COMPLETED').length;
console.log(`capability: rows=${reg.rows.length} records=${records.length} operationalErrors=${opErr} reproduced=${perRow.filter(r => r.identical).length}/${reg.rows.length} diffs=${diffs.length} requirements=${reqResults.filter(r => r.status === 'PASS').length}/${reqResults.length} compat=${['rq2', 'hb'].length ? 'see compat_check.json' : ''} frozen24=${pairProblems.length ? 'FAIL' : 'PASS'}`);
for (const [cls, v] of Object.entries(classes)) console.log(`  ${cls.padEnd(38)} n=${String(v.n).padStart(2)}  T0=${v.hard.T0} T1=${v.hard.T1} HB=${v.hard.HB} T2=${v.hard.T2} T3hard=${v.hard.T3} T3any=${v.any.T3}`);
