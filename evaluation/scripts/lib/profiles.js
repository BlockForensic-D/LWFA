'use strict';
// Shared profile entrypoints for capability evaluation, diagnostics, and benchmarking.
// All three paths use the same profile invocation logic.
//   T0  hash-only custody (harness function below, unchanged semantics from tier_replay.js)
//   T1  REF-LIFECYCLE         KIT/adapter/reference/verifier.js assessPackage
//   HB  HASH_COC_REFERENCE_1  HC/lib/baseline.js assessHashCoC (HashCoC baseline)
//   T2  PCC core              KIT/adapter/vendor/lwfa-v0.5.1/client/package.js assessPackage
//   T3  full PCC              KIT/disclosure/lib/assurance.js assessResearchPackage
const fs = require('node:fs'), path = require('node:path');
const {sha, readJson} = require('./common');

const PROFILE_IDS = ['T0', 'T1', 'HB', 'T2', 'T3'];

// T0: hash-only chain of custody. The delivered manifest must be the one anchored by the package
// record, and every delivered file/tool must match a hash anchored on the ledger. No request,
// version, checkpoint, scope, context or history semantics. Same logic as tier_replay.js t0(),
// now returning per-item results instead of a single flag.
function t0(K, dir, packageRecord, snapshot) {
  const ledger = new Set();
  for (const e of snapshot.records.values()) {
    if (e.kind !== 'MATERIAL_VERSION') continue;
    for (const b of K.P.blobItems([e])) ledger.add(b.descriptor.sha256);
    const d = e.body.data;
    if (e.body.materialType === 'PROCESS' && d.methodSpec?.executableDigest?.value) ledger.add(d.methodSpec.executableDigest.value);
  }
  const bytes = fs.readFileSync(path.join(dir, 'manifest.json'));
  const anchored = sha(bytes) === packageRecord.body.manifestHash;
  const x = JSON.parse(bytes.toString('utf8'));
  const check = (p, h) => {
    try { const raw = fs.readFileSync(path.join(dir, p)); return sha(raw) === h && ledger.has(h) ? 'HASH_MATCH' : 'HASH_MISMATCH'; }
    catch (e) { if (e.code !== 'ENOENT') throw e; return 'NOT_OBTAINED'; }
  };
  return {format: 'T0_HASH_ONLY_CUSTODY_1', manifestAnchored: anchored,
    materialResults: x.suppliedFiles.map(f => ({relativePath: f.relativePath, blobRef: f.blobRef, status: check(f.relativePath, f.blobRef.sha256)})),
    toolResults: x.tools.map(f => ({relativePath: f.relativePath, processRef: f.processRef, status: check(f.relativePath, f.sha256)}))};
}

// Builds the five zero-argument calls for one registry row on an already replayed snapshot.
function calls(K, CAMP, row, S, overrides = {}) {
  const snapshot = overrides.snapshot || S.snapshot, identities = overrides.identities || S.identities;
  const request = snapshot.records.get(row.requestRef.recordID), packageRecord = snapshot.records.get(row.packageRecordID);
  if (!request || !packageRecord) throw new Error('REGISTRY_RECORD_NOT_IN_SNAPSHOT ' + row.rowID);
  const caseDir = path.join(CAMP, 'cases', row.scenario);
  const dir = overrides.packageDir || path.join(caseDir, row.packageRelativePath);
  const presented = row.presentedDisclosurePath ? readJson(path.join(caseDir, row.presentedDisclosurePath)) : undefined;
  const pres = presented !== undefined ? {presentedDisclosure: presented} : {};
  return {
    T0: () => t0(K, dir, packageRecord, snapshot),
    T1: () => K.REF.assessPackage(dir, request, packageRecord, snapshot),
    HB: () => K.assessHashCoC({snapshot, identities, request, packageRecord, packageDir: dir,
      expectedCheckpoint: S.expected, actualChannel: S.expected.channelID, ...pres}),
    T2: () => K.P.assessPackage(dir, request, packageRecord, snapshot, S.cp),
    T3: () => K.assessResearchPackage({snapshot, request, identities, expectedCheckpoint: S.expected,
      actualChannel: S.expected.channelID, historyCheckpoint: S.cp, packageDir: dir, packageRecord, ...pres})
  };
}

module.exports = {PROFILE_IDS, t0, calls};
