'use strict';

// Pure JSON, commitment, and admission-shape functions. They do not authenticate
// actors, read committed state, or determine an assurance verdict.
const { createHash } = require('node:crypto');

const SCHEMA_VERSION = '1.0';
const LIMITS = Object.freeze({ jsonBytes: 1048576, depth: 64, nodes: 50000,
  version: 2147483647, idChars: 128, textChars: 16384 });
const HASH_PREFIX = 'LWFA\0v1\0';
const own = (v, k) => Object.prototype.hasOwnProperty.call(v, k);

class LWFAError extends Error {
  constructor(code, path, message) {
    super(`${code} at ${path}: ${message}`);
    this.name = 'LWFAError';
    this.code = code;
    this.path = path;
  }
}
function fail(code, path, message) { throw new LWFAError(code, path, message); }
function requireThat(ok, path, message, code = 'SCHEMA_ERROR') {
  if (!ok) fail(code, path, message);
}
function unicode(s, path) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(++i);
      requireThat(d >= 0xdc00 && d <= 0xdfff, path, 'unpaired surrogate', 'INVALID_UNICODE');
    } else requireThat(c < 0xdc00 || c > 0xdfff, path, 'unpaired surrogate', 'INVALID_UNICODE');
  }
}
function number(n, path) {
  requireThat(Number.isFinite(n), path, 'finite number required', 'INVALID_NUMBER');
  // LWFA restricts integral numbers to the exact interoperable range. Larger
  // integers (e.g. block numbers) use an explicitly defined decimal string.
  requireThat(!Number.isInteger(n) || Number.isSafeInteger(n), path,
    'unsafe integer; use a schema-defined string', 'INVALID_NUMBER');
}
function plain(v, path) {
  requireThat(v !== null && typeof v === 'object' && !Array.isArray(v), path, 'object required');
  const proto = Object.getPrototypeOf(v);
  requireThat(proto === Object.prototype || proto === null, path, 'plain object required');
  for (const key of Reflect.ownKeys(v)) {
    requireThat(typeof key === 'string', path, 'symbol keys are unsupported');
    unicode(key, path);
    const d = Object.getOwnPropertyDescriptor(v, key);
    requireThat(d.enumerable && own(d, 'value'), path, 'enumerable data properties required');
  }
  return v;
}
function shape(v, keys, path) {
  plain(v, path);
  requireThat(Object.keys(v).length === keys.length && keys.every(k => own(v, k)),
    path, `required fields: ${keys.join(', ')}`);
  return v;
}
function text(v, path, max = LIMITS.textChars) {
  requireThat(typeof v === 'string' && v.trim().length > 0 && v.length <= max,
    path, 'nonempty bounded string required');
  unicode(v, path);
  return v;
}
function id(v, path) {
  requireThat(typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v),
    path, 'invalid identifier');
}
function digest(v, path) {
  requireThat(typeof v === 'string' && /^[a-f0-9]{64}$/.test(v), path, 'lowercase SHA-256 hex required');
}
function version(v, path) {
  requireThat(Number.isInteger(v) && v >= 1 && v <= LIMITS.version, path, 'invalid positive version');
}
function sameCase(v, expected, path) {
  if (expected !== undefined) {
    id(expected, 'expectedCaseID');
    requireThat(v === expected, path, 'cross-case reference', 'CASE_MISMATCH');
  }
}
function list(v, path, min = 0) {
  requireThat(Array.isArray(v) && v.length >= min && v.length <= LIMITS.nodes,
    path, 'invalid list');
  // Also rejects sparse arrays and accessors before callers iterate them.
  canonicalJson(v);
  return v;
}

/** Parse JSON text before duplicate names (including escaped names) are lost. */
function parseJson(source) {
  requireThat(typeof source === 'string', '$', 'JSON text required', 'INVALID_JSON');
  requireThat(Buffer.byteLength(source, 'utf8') <= LIMITS.jsonBytes, '$', 'JSON too large', 'LIMIT_EXCEEDED');
  let pos = 0;
  let nodes = 0;
  const syntax = () => fail('INVALID_JSON', `$@${pos}`, 'invalid JSON syntax');
  const ws = () => { while (pos < source.length && /[\x20\t\r\n]/.test(source[pos])) pos++; };
  function string() {
    const start = pos++;
    while (pos < source.length) {
      const c = source[pos++];
      if (c === '"') {
        let value;
        try { value = JSON.parse(source.slice(start, pos)); } catch { syntax(); }
        unicode(value, `$@${start}`);
        return value;
      }
      if (c === '\\') pos++;
    }
    syntax();
  }
  function value(depth) {
    requireThat(depth <= LIMITS.depth && ++nodes <= LIMITS.nodes, '$', 'JSON complexity limit', 'LIMIT_EXCEEDED');
    ws();
    const c = source[pos];
    if (c === '"') return string();
    if (c === '{') {
      pos++; ws();
      const result = {};
      const seen = new Set();
      if (source[pos] === '}') { pos++; return result; }
      while (true) {
        if (source[pos] !== '"') syntax();
        const key = string();
        requireThat(!seen.has(key), `$@${pos}`, 'duplicate object key', 'DUPLICATE_KEY');
        seen.add(key); ws();
        if (source[pos++] !== ':') syntax();
        const entry = value(depth + 1);
        // __proto__ is a JSON key, never an instruction to change the prototype.
        Object.defineProperty(result, key, { value: entry, enumerable: true, writable: true, configurable: true });
        ws();
        if (source[pos] === '}') { pos++; return result; }
        if (source[pos++] !== ',') syntax();
        ws();
      }
    }
    if (c === '[') {
      pos++; ws();
      const result = [];
      if (source[pos] === ']') { pos++; return result; }
      while (true) {
        result.push(value(depth + 1)); ws();
        if (source[pos] === ']') { pos++; return result; }
        if (source[pos++] !== ',') syntax();
      }
    }
    for (const [token, v] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(token, pos)) { pos += token.length; return v; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(pos));
    if (!match) syntax();
    pos += match[0].length;
    const n = Number(match[0]); number(n, `$@${pos}`);
    // Non-zero inputs that underflow to zero are rejected.
    requireThat(n !== 0 || !/[1-9]/.test(match[0].split(/[eE]/)[0]),
      `$@${pos}`, 'numeric underflow', 'INVALID_NUMBER');
    return n;
  }
  const result = value(0); ws();
  if (pos !== source.length) syntax();
  return result;
}

/** RFC 8785 serialization for the narrower bounded LWFA JSON input profile. */
function canonicalJson(value) {
  const chunks = [];
  let bytes = 0;
  let nodes = 0;
  const active = new Set();
  function emit(s) {
    bytes += Buffer.byteLength(s, 'utf8');
    requireThat(bytes <= LIMITS.jsonBytes, '$', 'canonical JSON too large', 'LIMIT_EXCEEDED');
    chunks.push(s);
  }
  function visit(v, depth) {
    requireThat(depth <= LIMITS.depth && ++nodes <= LIMITS.nodes, '$', 'JSON complexity limit', 'LIMIT_EXCEEDED');
    if (v === null || typeof v === 'boolean') { emit(JSON.stringify(v)); return; }
    if (typeof v === 'string') { unicode(v, '$'); emit(JSON.stringify(v)); return; }
    if (typeof v === 'number') { number(v, '$'); emit(JSON.stringify(v)); return; }
    requireThat(typeof v === 'object', '$', 'unsupported JSON value', 'INVALID_JSON');
    requireThat(!active.has(v), '$', 'cyclic value', 'INVALID_JSON');
    active.add(v);
    if (Array.isArray(v)) {
      requireThat(Reflect.ownKeys(v).length === v.length + 1, '$', 'sparse or extended array', 'INVALID_JSON');
      emit('[');
      for (let i = 0; i < v.length; i++) {
        const d = Object.getOwnPropertyDescriptor(v, String(i));
        requireThat(d && d.enumerable && own(d, 'value'), '$', 'array data elements required', 'INVALID_JSON');
        if (i) emit(',');
        visit(d.value, depth + 1);
      }
      emit(']');
    } else {
      plain(v, '$'); emit('{');
      // Direct key serialization preserves canonical ordering; JSON.stringify(sortedObject)
      // would reorder integer-like property names according to JavaScript enumeration rules.
      const keys = Object.keys(v).sort();
      for (let i = 0; i < keys.length; i++) {
        if (i) emit(',');
        emit(JSON.stringify(keys[i])); emit(':'); visit(v[keys[i]], depth + 1);
      }
      emit('}');
    }
    active.delete(v);
  }
  visit(value, 0);
  return chunks.join('');
}
function hashBytes(bytes) {
  requireThat(bytes instanceof Uint8Array, '$', 'Buffer or Uint8Array required');
  return createHash('sha256').update(bytes).digest('hex');
}
function hashJson(domain, value) {
  requireThat(typeof domain === 'string' && /^[A-Z_]{1,32}$/.test(domain), 'domain', 'invalid hash domain');
  return createHash('sha256').update(HASH_PREFIX + domain + '\0', 'utf8')
    .update(canonicalJson(value), 'utf8').digest('hex');
}

function assertActorRef(v) {
  shape(v, ['mspID', 'clientID'], 'actor'); id(v.mspID, 'actor.mspID');
  text(v.clientID, 'actor.clientID', 4096);
  requireThat(!/[\x00-\x1f\x7f]/.test(v.clientID), 'actor.clientID', 'control characters forbidden');
  return v;
}
function assertMaterialRef(v, caseID) {
  shape(v, ['caseID', 'objectID', 'version', 'commitment'], 'materialRef');
  id(v.caseID, 'materialRef.caseID'); id(v.objectID, 'materialRef.objectID');
  version(v.version, 'materialRef.version'); digest(v.commitment, 'materialRef.commitment');
  sameCase(v.caseID, caseID, 'materialRef.caseID'); return v;
}
function assertRecordRef(v, caseID) {
  shape(v, ['caseID', 'recordID', 'kind', 'commitment'], 'recordRef');
  id(v.caseID, 'recordRef.caseID'); id(v.recordID, 'recordRef.recordID');
  id(v.kind, 'recordRef.kind'); digest(v.commitment, 'recordRef.commitment');
  sameCase(v.caseID, caseID, 'recordRef.caseID'); return v;
}
function assertProfileRef(v) {
  shape(v, ['profileKind', 'profileID', 'version', 'sha256'], 'profileRef');
  id(v.profileKind, 'profileRef.profileKind'); id(v.profileID, 'profileRef.profileID');
  version(v.version, 'profileRef.version'); digest(v.sha256, 'profileRef.sha256'); return v;
}
function assertBlobDescriptor(v) {
  shape(v, ['slotID', 'sha256', 'byteLength', 'mediaType'], 'blob');
  id(v.slotID, 'blob.slotID'); digest(v.sha256, 'blob.sha256');
  requireThat(Number.isSafeInteger(v.byteLength) && v.byteLength >= 0, 'blob.byteLength', 'invalid byte length');
  text(v.mediaType, 'blob.mediaType', 255);
  requireThat(!/[\s\x00-\x1f\x7f]/.test(v.mediaType), 'blob.mediaType', 'whitespace/control forbidden');
  return v;
}
function assertBlobRef(v, caseID) {
  shape(v, ['ownerVersionRef', 'slotID', 'sha256'], 'blobRef');
  assertMaterialRef(v.ownerVersionRef, caseID); id(v.slotID, 'blobRef.slotID');
  digest(v.sha256, 'blobRef.sha256'); return v;
}
function assertCheckpoint(v) {
  shape(v, ['channelID', 'blockNumber', 'blockHeaderHash'], 'checkpoint');
  id(v.channelID, 'checkpoint.channelID'); digest(v.blockHeaderHash, 'checkpoint.blockHeaderHash');
  requireThat(typeof v.blockNumber === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v.blockNumber),
    'checkpoint.blockNumber', 'canonical uint64 decimal string required');
  requireThat(BigInt(v.blockNumber) <= 18446744073709551615n, 'checkpoint.blockNumber', 'uint64 overflow');
  return v;
}
function assertKnowledge(v) {
  plain(v, 'knowledge');
  if (v.status === 'VALUE') {
    shape(v, ['status', 'value'], 'knowledge');
    requireThat(v.value !== null, 'knowledge.value', 'VALUE cannot be null'); canonicalJson(v.value);
  } else {
    shape(v, ['status', 'reason'], 'knowledge');
    requireThat(['UNKNOWN', 'NOT_APPLICABLE'].includes(v.status), 'knowledge.status', 'invalid status');
    text(v.reason, 'knowledge.reason');
  }
  // NOT_APPLICABLE remains subject to admission policy at a later layer.
  return v;
}
function assertInputBinding(v, caseID) {
  plain(v, 'input');
  requireThat(['BLOB', 'RECORD'].includes(v.inputType), 'input.inputType', 'invalid input type');
  shape(v, v.inputType === 'BLOB' ? ['inputType', 'inputID', 'sourceRef', 'slotID', 'sha256']
    : ['inputType', 'inputID', 'sourceRef'], 'input');
  id(v.inputID, 'input.inputID'); assertMaterialRef(v.sourceRef, caseID);
  if (v.inputType === 'BLOB') { id(v.slotID, 'input.slotID'); digest(v.sha256, 'input.sha256'); }
  return v;
}

/** Only explicit material-reference sets are deduplicated/sorted. */
function sortMaterialRefs(refs, caseID) {
  list(refs, 'refs');
  const byIdentity = new Map();
  for (const ref of refs) {
    assertMaterialRef(ref, caseID);
    const identity = canonicalJson([ref.caseID, ref.objectID, ref.version]);
    const serialized = canonicalJson(ref);
    requireThat(!byIdentity.has(identity) || byIdentity.get(identity) === serialized,
      'refs', 'same version with conflicting commitment', 'CONFLICTING_REFERENCE');
    byIdentity.set(identity, serialized);
  }
  return [...byIdentity.values()].sort().map(parseJson);
}

/** Extract dependency obligations, not full material/admission validation. */
function deriveDirectDeps(materialType, data, caseID) {
  id(caseID, 'caseID'); plain(data, 'data');
  let refs;
  switch (materialType) {
    case 'CONTEXT':
      requireThat(data.subtype === 'INCIDENT', 'data.subtype', 'INCIDENT required'); refs = []; break;
    case 'ARTIFACT': refs = [data.incidentRef]; break;
    case 'PROCESS': {
      list(data.inputBindings, 'data.inputBindings', 1);
      const inputs = new Set();
      refs = data.inputBindings.map(v => {
        assertInputBinding(v, caseID);
        requireThat(!inputs.has(v.inputID), 'data.inputBindings', 'duplicate inputID', 'DUPLICATE_ID');
        inputs.add(v.inputID); return v.sourceRef;
      }); break;
    }
    case 'FINDING': refs = list(data.supportRefs, 'data.supportRefs'); break;
    case 'REPORT': {
      list(data.claims, 'data.claims', 1);
      const claims = new Set(); refs = [];
      for (const claim of data.claims) {
        shape(claim, ['claimID', 'statement', 'findingRefs', 'documentLocator'], 'claim');
        id(claim.claimID, 'claim.claimID'); text(claim.statement, 'claim.statement');
        text(claim.documentLocator, 'claim.documentLocator');
        requireThat(!claims.has(claim.claimID), 'data.claims', 'duplicate claimID', 'DUPLICATE_ID');
        claims.add(claim.claimID); refs.push(...list(claim.findingRefs, 'claim.findingRefs', 1));
      } break;
    }
    default: fail('SCHEMA_ERROR', 'materialType', 'unknown material type');
  }
  return sortMaterialRefs(refs, caseID);
}
function assertDirectDeps(materialType, data, directDeps, caseID) {
  const expected = deriveDirectDeps(materialType, data, caseID);
  list(directDeps, 'directDeps');
  directDeps.forEach(ref => assertMaterialRef(ref, caseID));
  requireThat(canonicalJson(directDeps) === canonicalJson(expected), 'directDeps',
    'expected the exact sorted unique dependency list', 'DEPENDENCY_MISMATCH');
  return directDeps;
}

const ENVELOPE_KEYS = ['schemaVersion', 'caseID', 'recordID', 'kind', 'actor', 'admissionPolicyRef', 'body'];
function assertEnvelope(v, committed) {
  shape(v, committed ? [...ENVELOPE_KEYS, 'commitment'] : ENVELOPE_KEYS, 'envelope');
  requireThat(v.schemaVersion === SCHEMA_VERSION, 'schemaVersion', 'unsupported schema version');
  id(v.caseID, 'caseID'); id(v.recordID, 'recordID'); id(v.kind, 'kind');
  assertActorRef(v.actor); assertProfileRef(v.admissionPolicyRef); plain(v.body, 'body');
  if (committed) digest(v.commitment, 'commitment');
  canonicalJson(v);
}
function envelopePreimage(v) {
  return Object.fromEntries(ENVELOPE_KEYS.map(k => [k, v[k]]));
}
function commitEnvelope(envelope) {
  assertEnvelope(envelope, false);
  const result = parseJson(canonicalJson(envelope));
  result.commitment = hashJson('RECORD', result);
  // A successful builder must never emit a record its own parser/verifier
  // rejects: the size limit includes the newly added commitment field.
  canonicalJson(result);
  return result;
}
function verifyEnvelopeCommitment(envelope) {
  assertEnvelope(envelope, true);
  requireThat(hashJson('RECORD', envelopePreimage(envelope)) === envelope.commitment,
    'commitment', 'envelope commitment mismatch', 'COMMITMENT_MISMATCH');
  // Success ONLY means self-consistent structure and commitment. An untrusted
  // actor can rehash a fabricated record; ledger comparison is still required.
  return envelope;
}

// P1 admission schema. These pure validators establish syntax and declared
// obligations only. The contract still authenticates actors and resolves each
// material reference against committed state before admission.
const ROLES = Object.freeze(['AcquisitionOperator', 'ForensicInvestigator',
  'AssuranceReviewer', 'IndependentReviewer']);
const MATERIAL_TYPES = Object.freeze(['CONTEXT', 'ARTIFACT', 'PROCESS', 'FINDING', 'REPORT']);
const MATERIAL_KEYS = ['objectID', 'materialType', 'predecessorRef', 'formationContext', 'directDeps', 'data'];
function cloneJson(value) { return parseJson(canonicalJson(value)); }
function strings(value, path, minimum = 0) {
  list(value, path, minimum).forEach((entry, i) => text(entry, `${path}[${i}]`));
  return value;
}
function knowledgeOf(value, path, valueValidator, allowNA = false) {
  assertKnowledge(value);
  if (value.status === 'VALUE') valueValidator(value.value, `${path}.value`);
  requireThat(allowNA || value.status !== 'NOT_APPLICABLE', path,
    'NOT_APPLICABLE is not allowed by alpha0');
  return value;
}
function timestamp(value, path) {
  requireThat(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value),
    path, 'UTC timestamp with millisecond precision required');
  const date = new Date(value);
  requireThat(Number.isFinite(date.getTime()) && date.toISOString() === value,
    path, 'invalid calendar timestamp');
}
function timeKnowledge(value, path) { return knowledgeOf(value, path, timestamp); }
function uniqueActors(value, path, minimum = 0) {
  list(value, path, minimum);
  requireThat(value.length <= 100, path, 'at most 100 actors');
  const seen = new Set();
  value.forEach(actor => {
    assertActorRef(actor);
    const key = canonicalJson(actor);
    requireThat(!seen.has(key), path, 'duplicate actor', 'DUPLICATE_ID');
    seen.add(key);
  });
  return value;
}
function sortProfileRefs(value) {
  list(value, 'profileRefs', 1);
  requireThat(value.length <= 100, 'profileRefs', 'at most 100 profiles');
  const refs = new Map();
  for (const ref of value) {
    assertProfileRef(ref);
    const key = canonicalJson([ref.profileKind, ref.profileID, ref.version]);
    const serialized = canonicalJson(ref);
    requireThat(!refs.has(key) || refs.get(key) === serialized, 'profileRefs',
      'same profile version has conflicting digest', 'CONFLICTING_REFERENCE');
    refs.set(key, serialized);
  }
  return [...refs.values()].sort().map(parseJson);
}
function operationInput(value, bodyField) {
  shape(value, ['schemaVersion', 'caseID', 'operationID', 'recordID', bodyField], 'input');
  requireThat(value.schemaVersion === SCHEMA_VERSION, 'schemaVersion', 'unsupported schema version');
  id(value.caseID, 'caseID'); id(value.operationID, 'operationID'); id(value.recordID, 'recordID');
}
function validateInitializeInput(rawObject) {
  const value = cloneJson(rawObject);
  operationInput(value, 'config');
  const config = value.config;
  shape(config, ['title', 'members', 'leadInvestigator', 'reviewers', 'profileRefs'], 'config');
  text(config.title, 'config.title');
  list(config.members, 'config.members', 1);
  requireThat(config.members.length <= 100, 'config.members', 'at most 100 members');
  const members = new Map();
  for (const member of config.members) {
    shape(member, ['actor', 'roles'], 'member'); assertActorRef(member.actor);
    list(member.roles, 'member.roles', 1);
    requireThat(member.roles.length <= ROLES.length, 'member.roles', 'invalid roles');
    const roles = new Set();
    for (const role of member.roles) {
      requireThat(ROLES.includes(role) && !roles.has(role), 'member.roles',
        'roles must be supported and unique');
      roles.add(role);
    }
    member.roles.sort();
    const key = canonicalJson(member.actor);
    requireThat(!members.has(key), 'config.members', 'duplicate actor', 'DUPLICATE_ID');
    members.set(key, roles);
  }
  assertActorRef(config.leadInvestigator);
  requireThat(members.get(canonicalJson(config.leadInvestigator))?.has('ForensicInvestigator'),
    'config.leadInvestigator', 'lead must be a ForensicInvestigator member');
  uniqueActors(config.reviewers, 'config.reviewers', 1);
  for (const reviewer of config.reviewers) {
    requireThat(members.get(canonicalJson(reviewer))?.has('IndependentReviewer'),
      'config.reviewers', 'reviewer must be an IndependentReviewer member');
  }
  config.profileRefs = sortProfileRefs(config.profileRefs);
  // Membership and reviewer collections are sets; no user-visible narrative
  // ordering is changed (unlike claims, input bindings, and evidence arrays).
  config.members.sort((a, b) => canonicalJson(a.actor) < canonicalJson(b.actor) ? -1 : 1);
  config.reviewers.sort((a, b) => canonicalJson(a) < canonicalJson(b) ? -1 : 1);
  return value;
}
function formationContext(value) {
  shape(value, ['purpose', 'declaredRecordedTime'], 'formationContext');
  text(value.purpose, 'formationContext.purpose');
  timeKnowledge(value.declaredRecordedTime, 'formationContext.declaredRecordedTime');
}
function materialData(material, caseID) {
  const data = material.data;
  plain(data, 'data');
  switch (material.materialType) {
    case 'CONTEXT': {
      shape(data, ['subtype', 'reportedSource', 'incidentSummary', 'affectedAssets',
        'initialScope', 'claimedEventTime', 'declaredRecordedTime', 'gaps'], 'data');
      requireThat(data.subtype === 'INCIDENT', 'data.subtype', 'INCIDENT required');
      text(data.reportedSource, 'data.reportedSource');
      text(data.incidentSummary, 'data.incidentSummary');
      strings(data.affectedAssets, 'data.affectedAssets', 1); text(data.initialScope, 'data.initialScope');
      timeKnowledge(data.claimedEventTime, 'data.claimedEventTime');
      timeKnowledge(data.declaredRecordedTime, 'data.declaredRecordedTime');
      requireThat(canonicalJson(data.declaredRecordedTime) ===
        canonicalJson(material.formationContext.declaredRecordedTime), 'data.declaredRecordedTime',
      'must equal formationContext.declaredRecordedTime');
      strings(data.gaps, 'data.gaps');
      break;
    }
    case 'ARTIFACT': {
      shape(data, ['incidentRef', 'acquisitionMethod', 'sourceDescription', 'collectionBoundary',
        'claimedPerformer', 'blobDescriptor', 'limitations'], 'data');
      assertMaterialRef(data.incidentRef, caseID);
      text(data.acquisitionMethod, 'data.acquisitionMethod');
      text(data.sourceDescription, 'data.sourceDescription');
      text(data.collectionBoundary, 'data.collectionBoundary');
      knowledgeOf(data.claimedPerformer, 'data.claimedPerformer', text);
      assertBlobDescriptor(data.blobDescriptor); strings(data.limitations, 'data.limitations');
      break;
    }
    case 'PROCESS': {
      plain(data.methodSpec, 'data.methodSpec');
      const manual = data.methodSpec.mode === 'MANUAL';
      const keys = ['phase', 'inputBindings', 'methodSpec', 'parameters', 'environment', 'outputs', 'gaps'];
      shape(data, manual ? [...keys, 'resultSummary'] : keys, 'data');
      requireThat(['EXAMINATION', 'ANALYSIS'].includes(data.phase), 'data.phase', 'unsupported phase');
      list(data.inputBindings, 'data.inputBindings', 1);
      data.inputBindings.forEach(binding => assertInputBinding(binding, caseID));
      if (manual) {
        shape(data.methodSpec, ['mode', 'name', 'rationale'], 'data.methodSpec');
        text(data.methodSpec.name, 'data.methodSpec.name');
        text(data.methodSpec.rationale, 'data.methodSpec.rationale');
        text(data.resultSummary, 'data.resultSummary');
      } else {
        shape(data.methodSpec, ['mode', 'name', 'version', 'executableDigest'], 'data.methodSpec');
        requireThat(data.methodSpec.mode === 'TOOL', 'data.methodSpec.mode', 'MANUAL or TOOL required');
        text(data.methodSpec.name, 'data.methodSpec.name');
        knowledgeOf(data.methodSpec.version, 'data.methodSpec.version', text);
        knowledgeOf(data.methodSpec.executableDigest, 'data.methodSpec.executableDigest', digest);
      }
      knowledgeOf(data.parameters, 'data.parameters', plain, manual);
      knowledgeOf(data.environment, 'data.environment', (entry, path) => {
        plain(entry, path); requireThat(Object.keys(entry).length > 0, path, 'nonempty environment required');
      }, manual);
      list(data.outputs, 'data.outputs', manual ? 0 : 1);
      const slots = new Set();
      for (const descriptor of data.outputs) {
        assertBlobDescriptor(descriptor);
        requireThat(!slots.has(descriptor.slotID), 'data.outputs', 'duplicate output slotID', 'DUPLICATE_ID');
        slots.add(descriptor.slotID);
      }
      strings(data.gaps, 'data.gaps');
      break;
    }
    case 'FINDING': {
      const unsupported = data.supportStatus === 'DECLARED_UNSUPPORTED';
      const keys = ['statement', 'claimType', 'rationale', 'assumptions', 'interpretationLimits',
        'supportRefs', 'supportStatus'];
      shape(data, unsupported ? [...keys, 'unsupportedReason'] : keys, 'data');
      text(data.statement, 'data.statement'); text(data.rationale, 'data.rationale');
      requireThat(['OBSERVATION', 'INTERPRETATION', 'HYPOTHESIS'].includes(data.claimType),
        'data.claimType', 'unsupported claim type');
      strings(data.assumptions, 'data.assumptions'); strings(data.interpretationLimits, 'data.interpretationLimits');
      data.supportRefs = sortMaterialRefs(data.supportRefs, caseID);
      if (unsupported) {
        requireThat(data.claimType === 'HYPOTHESIS' && data.supportRefs.length === 0,
          'data.supportStatus', 'unsupported status requires a hypothesis with zero support');
        text(data.unsupportedReason, 'data.unsupportedReason');
      } else {
        requireThat(data.supportStatus === 'SUPPORT_DECLARED' && data.supportRefs.length > 0,
          'data.supportStatus', 'declared support requires at least one reference');
      }
      break;
    }
    case 'REPORT': {
      shape(data, ['documentDescriptor', 'claims'], 'data');
      assertBlobDescriptor(data.documentDescriptor); list(data.claims, 'data.claims', 1);
      for (const claim of data.claims) {
        shape(claim, ['claimID', 'statement', 'findingRefs', 'documentLocator'], 'claim');
        id(claim.claimID, 'claim.claimID'); text(claim.statement, 'claim.statement');
        text(claim.documentLocator, 'claim.documentLocator');
        claim.findingRefs = sortMaterialRefs(claim.findingRefs, caseID);
        requireThat(claim.findingRefs.length > 0, 'claim.findingRefs', 'at least one finding required');
      }
      break;
    }
  }
}
function normalizeMaterial(value, caseID, allocatedVersion) {
  shape(value, allocatedVersion ? [...MATERIAL_KEYS, 'version'] : MATERIAL_KEYS, 'material');
  id(caseID, 'caseID'); id(value.objectID, 'material.objectID');
  requireThat(MATERIAL_TYPES.includes(value.materialType), 'material.materialType', 'unknown material type');
  if (value.predecessorRef !== null) {
    assertMaterialRef(value.predecessorRef, caseID);
    requireThat(value.predecessorRef.objectID === value.objectID, 'material.predecessorRef',
      'predecessor must belong to the same object');
  }
  if (allocatedVersion) {
    version(value.version, 'material.version');
    requireThat(value.version === 1 ? value.predecessorRef === null :
      value.predecessorRef !== null && value.predecessorRef.version < value.version,
    'material.predecessorRef', 'first version has no predecessor; later versions need an older predecessor');
  }
  formationContext(value.formationContext);
  materialData(value, caseID);
  value.directDeps = sortMaterialRefs(value.directDeps, caseID);
  assertDirectDeps(value.materialType, value.data, value.directDeps, caseID);
  return value;
}
function validateRegisterInput(rawObject) {
  const value = cloneJson(rawObject);
  operationInput(value, 'material');
  normalizeMaterial(value.material, value.caseID, false);
  return value;
}
function validateMaterialBody(body, caseID) {
  return normalizeMaterial(cloneJson(body), caseID, true);
}
function materialRef(envelope) {
  verifyEnvelopeCommitment(envelope);
  requireThat(envelope.kind === 'MATERIAL_VERSION', 'envelope.kind', 'MATERIAL_VERSION required');
  validateMaterialBody(envelope.body, envelope.caseID);
  return { caseID: envelope.caseID, objectID: envelope.body.objectID,
    version: envelope.body.version, commitment: envelope.commitment };
}
function recordRef(envelope) {
  verifyEnvelopeCommitment(envelope);
  return { caseID: envelope.caseID, recordID: envelope.recordID,
    kind: envelope.kind, commitment: envelope.commitment };
}
function validateDeployment(deployment) {
  const result = cloneJson(deployment);
  shape(result, ['roleAttribute', 'roleMSPs'], 'deployment');
  id(result.roleAttribute, 'deployment.roleAttribute');
  shape(result.roleMSPs, ROLES, 'deployment.roleMSPs');
  for (const role of ROLES) {
    const entries = list(result.roleMSPs[role], `deployment.roleMSPs.${role}`);
    requireThat(entries.length <= 100, `deployment.roleMSPs.${role}`, 'at most 100 MSP IDs');
    const seen = new Set();
    for (const mspID of entries) {
      id(mspID, `deployment.roleMSPs.${role}`);
      requireThat(!seen.has(mspID), `deployment.roleMSPs.${role}`, 'duplicate MSP ID', 'DUPLICATE_ID');
      seen.add(mspID);
    }
    entries.sort();
  }
  // Empty mappings are valid configuration but must deny every writer. This
  // portable source bundle never guesses an actual organization's MSP ID.
  return result;
}
const ADMISSION_DEFINITION = {
  profileKind: 'ADMISSION', profileID: 'alpha0', version: 5, schemaVersion: SCHEMA_VERSION,
  materialTypes: MATERIAL_TYPES,
  roles: ROLES,
  rules: {
    versioning: 'IMMUTABLE_SEQUENTIAL_VERSIONS_WITH_EXPLICIT_OLDER_PREDECESSOR',
    dependencies: 'EXACT_SORTED_UNIQUE_DECLARED_REFERENCES_SAME_CASE_COMMITTED',
    formationContext: 'PURPOSE_AND_DECLARED_UTC_TIME_OR_EXPLAINED_UNKNOWN',
    timestamp: 'UTC_ISO8601_MILLISECONDS_CALENDAR_VALID',
    incident: 'INCIDENT_ROOT_AND_MATCHING_DECLARED_RECORDED_TIME',
    artifact: 'INCIDENT_DEPENDENCY_AND_SINGLE_BOUND_BLOB',
    process: 'EXAMINATION_OR_ANALYSIS_WITH_DISTINCT_INPUT_IDS',
    inputBlob: 'ARTIFACT_BLOB_OR_PROCESS_OUTPUT_WITH_EXACT_SLOT_AND_DIGEST',
    inputRecord: 'MANUAL_PROCESS_RESULT_SUMMARY',
    manual: 'NAMED_METHOD_RATIONALE_NONEMPTY_RESULT_OPTIONAL_OUTPUTS',
    tool: 'NAMED_METHOD_VERSION_AND_DIGEST_VALUE_OR_UNKNOWN_NONEMPTY_OUTPUTS',
    parameters: 'OBJECT_VALUE_OR_UNKNOWN_NOT_APPLICABLE_ONLY_MANUAL',
    environment: 'NONEMPTY_OBJECT_VALUE_OR_UNKNOWN_NOT_APPLICABLE_ONLY_MANUAL',
    finding: 'ARTIFACT_OR_PROCESS_SUPPORT_DECLARED_UNSUPPORTED_ONLY_HYPOTHESIS_WITH_REASON',
    report: 'NONEMPTY_UNIQUE_CLAIM_IDS_EACH_WITH_FINDING_REFERENCES_AND_DOCUMENT_LOCATOR',
    uncertainty: 'EXPLICIT_UNKNOWN_WITH_REASON_DOES_NOT_ESTABLISH_RERUN_SUFFICIENCY',
    registration: 'STRUCTURAL_ADMISSION_DOES_NOT_ESTABLISH_EVIDENCE_OR_CLAIM_TRUTH',
    revisionAuthority: 'OWNER_OR_CASE_LEAD_WITH_CURRENT_ROLE_AND_TYPE_PERMISSION',
    authentication: 'TRANSACTION_IDENTITY_ROLE_ATTRIBUTE_AND_DEPLOYMENT_MSP_MAPPING',
    initialization: 'ASSURANCE_REVIEWER_CREATOR_AND_ASSIGNED_CASE_MEMBERS',
    profileChanges: 'REQUIRE_IMPLEMENTATION_AND_PROFILE_VERSION_CHANGE',
    caseProfiles: 'CURRENT_ADMISSION_REQUIRED_OTHER_REFERENCES_EXACT_BUNDLED_ALLOWLIST',
    reviewProfiles: 'FULL_REFERENCE_MATCH_AND_CASE_AUTHORIZATION_BEFORE_NEW_REVIEW',
    reviewSources: 'COMMITTED_EXTRA_ROOTS_AND_EXACT_SEALED_TOOL_INPUT_OUTPUT_ENVIRONMENT',
    observationChecks: 'EXACT_CHECK_IDS_BLOB_DESCRIPTORS_AND_SEALED_EXECUTION_BASIS',
    observationAttempt: 'CREATE_ONLY_CASE_REQUEST_REVIEWER_ATTEMPT_AFTER_RECEIPT_CHECK',
    observationHistory: 'ACTUAL_CHANNEL_ALL_MODES_CHECKS_AFTER_BASIS_REJECTION_INDEPENDENT_OF_BAD_BASIS',
    legacyWrites: 'CURRENT_PROFILE_REQUIRED_NO_IMPLICIT_STATE_MIGRATION',
    issues: 'CASE_MEMBER_EXACT_MATERIAL_OR_REQUEST_TARGET_WITH_SAME_CASE_SUPPORT',
    responses: 'CREATOR_OWNER_OR_CASE_LEAD_NO_AUTOMATIC_CLOSURE',
    dispositions: 'CHALLENGE_ONLY_WITH_AUTHORITY_FRESH_SEQUENCE_AND_NO_SELF_JUDGMENT',
  },
};
function getAdmissionProfile() {
  return supportedDefinition('admission', ADMISSION_DEFINITION);
}

// v0.4 admits attributable rerun records; admission is not proof of execution.
function recordRefKind(value, caseID, kind, path) {
  assertRecordRef(value, caseID);
  requireThat(value.kind === kind, path, `${kind} reference required`);
}
function uniqueBy(values, path, identity) {
  const seen = new Set();
  for (const value of values) {
    const key = identity(value);
    requireThat(!seen.has(key), path, 'duplicate identity', 'DUPLICATE_ID');
    seen.add(key);
  }
}
function compareCanonical(a, b) {
  const left = canonicalJson(a); const right = canonicalJson(b);
  return left < right ? -1 : left > right ? 1 : 0;
}
function reviewBody(value, caseID) {
  id(caseID, 'caseID');
  shape(value, ['targetRef', 'reviewerActorRef', 'scope', 'checkpointBasis',
    'policyRef', 'verifierSpecRef', 'checkPlan', 'predecessorRequestRef'], 'review');
  assertMaterialRef(value.targetRef, caseID); assertActorRef(value.reviewerActorRef);
  shape(value.scope, ['purpose', 'extraRoots'], 'review.scope');
  text(value.scope.purpose, 'review.scope.purpose');
  value.scope.extraRoots = sortMaterialRefs(value.scope.extraRoots, caseID);
  assertCheckpoint(value.checkpointBasis);
  assertProfileRef(value.policyRef); assertProfileRef(value.verifierSpecRef);
  requireThat(value.policyRef.profileKind === 'POLICY', 'review.policyRef', 'POLICY reference required');
  requireThat(value.verifierSpecRef.profileKind === 'VERIFIER', 'review.verifierSpecRef', 'VERIFIER reference required');
  if (value.predecessorRequestRef !== null) {
    recordRefKind(value.predecessorRequestRef, caseID, 'REVIEW_REQUEST', 'review.predecessorRequestRef');
  }
  list(value.checkPlan, 'review.checkPlan');
  requireThat(value.checkPlan.length <= 100, 'review.checkPlan', 'at most 100 checks');
  for (const check of value.checkPlan) {
    shape(check, ['checkID', 'checkType', 'processRef', 'inputBindings', 'expectedOutputs',
      'comparator', 'requiredEnvironment'], 'check');
    id(check.checkID, 'check.checkID');
    requireThat(check.checkType === 'RERUN_PROCESS', 'check.checkType', 'only RERUN_PROCESS is supported');
    assertMaterialRef(check.processRef, caseID);
    list(check.inputBindings, 'check.inputBindings', 1);
    for (const binding of check.inputBindings) assertInputBinding(binding, caseID);
    uniqueBy(check.inputBindings, 'check.inputBindings', value => value.inputID);
    list(check.expectedOutputs, 'check.expectedOutputs', 1);
    check.expectedOutputs.forEach(assertBlobDescriptor);
    uniqueBy(check.expectedOutputs, 'check.expectedOutputs', value => value.slotID);
    requireThat(check.comparator === 'JSON_CANONICAL_EQUAL', 'check.comparator', 'unsupported comparator');
    knowledgeOf(check.requiredEnvironment, 'check.requiredEnvironment', (value, path) => {
      plain(value, path); requireThat(Object.keys(value).length > 0, path, 'nonempty environment required');
    });
    // Input/output sequence must still match the historical PROCESS; only
    // explicit reference sets, not procedure array order, are normalized.
  }
  uniqueBy(value.checkPlan, 'review.checkPlan', value => value.checkID);
  return value;
}
function validateReviewInput(rawObject) {
  const value = cloneJson(rawObject); operationInput(value, 'review');
  reviewBody(value.review, value.caseID); return value;
}
function validateReviewBody(body, caseID) { return reviewBody(cloneJson(body), caseID); }
function packageBody(value, caseID) {
  id(caseID, 'caseID');
  shape(value, ['requestRef', 'manifestHash', 'formatVersion', 'declaredExporter'], 'package');
  recordRefKind(value.requestRef, caseID, 'REVIEW_REQUEST', 'package.requestRef');
  digest(value.manifestHash, 'package.manifestHash');
  requireThat(value.formatVersion === 'LWFA_PACKAGE_2', 'package.formatVersion', 'unsupported package format');
  knowledgeOf(value.declaredExporter, 'package.declaredExporter', text);
  return value;
}
function validatePackageInput(rawObject) {
  const value = cloneJson(rawObject); operationInput(value, 'package');
  packageBody(value.package, value.caseID); return value;
}
function validatePackageBody(body, caseID) { return packageBody(cloneJson(body), caseID); }

// All execution fields are reviewer-attributed. Off-chain bytes are verified by
// the client; consensus only validates declaration shape and ledger bindings.
function validateExecution(e, status, caseID) {
  shape(e, ['processRef', 'toolDigest', 'inputBindings', 'parameters', 'environment',
    'expectedOutputs', 'actualOutputs', 'comparisons', 'comparator', 'comparatorVersion',
    'runner', 'startedAt', 'finishedAt', 'exitCode', 'signal', 'errorCode',
    'stdoutSha256', 'stderrSha256'], 'execution');
  assertMaterialRef(e.processRef, caseID); digest(e.toolDigest, 'execution.toolDigest');
  list(e.inputBindings, 'execution.inputBindings', 1);
  e.inputBindings.forEach(v => assertInputBinding(v, caseID));
  uniqueBy(e.inputBindings, 'execution.inputBindings', v => v.inputID);
  knowledgeOf(e.parameters, 'execution.parameters', plain);
  knowledgeOf(e.environment, 'execution.environment', plain);
  requireThat(e.parameters.status === 'VALUE' && e.environment.status === 'VALUE',
    'execution', 'executed results require explicit parameters and environment');
  list(e.expectedOutputs, 'execution.expectedOutputs', 1); e.expectedOutputs.forEach(assertBlobDescriptor);
  list(e.actualOutputs, 'execution.actualOutputs'); e.actualOutputs.forEach(assertBlobDescriptor);
  uniqueBy(e.expectedOutputs, 'execution.expectedOutputs', v => v.slotID);
  uniqueBy(e.actualOutputs, 'execution.actualOutputs', v => v.slotID);
  requireThat(e.comparator === 'JSON_CANONICAL_EQUAL' && e.comparatorVersion === '1',
    'execution.comparator', 'unsupported comparator or version');
  shape(e.runner, ['name', 'version', 'sha256'], 'execution.runner');
  requireThat(e.runner.name === 'lwfa-docker-runner' && e.runner.version === '0.4.0',
    'execution.runner', 'unsupported runner identity'); digest(e.runner.sha256, 'execution.runner.sha256');
  timestamp(e.startedAt, 'execution.startedAt'); timestamp(e.finishedAt, 'execution.finishedAt');
  requireThat(e.finishedAt >= e.startedAt, 'execution.finishedAt', 'finish precedes start');
  requireThat(e.exitCode === null || (Number.isInteger(e.exitCode) && e.exitCode >= 0 && e.exitCode <= 255),
    'execution.exitCode', 'invalid process exit code');
  if (e.signal !== null) id(e.signal, 'execution.signal');
  if (e.errorCode !== null) id(e.errorCode, 'execution.errorCode');
  digest(e.stdoutSha256, 'execution.stdoutSha256'); digest(e.stderrSha256, 'execution.stderrSha256');
  list(e.comparisons, 'execution.comparisons');
  if (status === 'EXECUTION_ERROR') {
    requireThat(['TIMEOUT', 'RUNNER_ERROR', 'NONZERO_EXIT', 'INVALID_OUTPUT_JSON'].includes(e.errorCode) && e.comparisons.length === 0, 'execution',
      'execution errors require a cause and no comparison verdict');
    requireThat(e.errorCode !== 'OUTPUT_DIFFERENT', 'execution.errorCode', 'a difference is not an execution error');
    if (e.errorCode === 'NONZERO_EXIT') requireThat(e.exitCode !== null && e.exitCode !== 0, 'execution.exitCode', 'nonzero exit required');
    if (e.errorCode === 'INVALID_OUTPUT_JSON') requireThat(e.exitCode === 0 && e.signal === null, 'execution.exitCode', 'parser failure must follow successful process exit');
    return e;
  }
  requireThat(e.exitCode === 0 && e.signal === null && e.errorCode === null,
    'execution', 'completed comparisons require successful execution');
  if (e.actualOutputs.length === 1) requireThat(e.stdoutSha256 === e.actualOutputs[0].sha256,
    'execution.stdoutSha256', 'single JSON output must match captured stdout digest');
  const expected = e.expectedOutputs.map(v => v.slotID).sort();
  const actual = e.actualOutputs.map(v => v.slotID).sort();
  requireThat(canonicalJson(expected) === canonicalJson(actual), 'execution.actualOutputs', 'output coverage differs');
  uniqueBy(e.comparisons, 'execution.comparisons', v => v.slotID);
  requireThat(canonicalJson(e.comparisons.map(v => v.slotID).sort()) === canonicalJson(expected),
    'execution.comparisons', 'one comparison per output slot required');
  for (const c of e.comparisons) {
    shape(c, ['slotID', 'expectedCanonicalSha256', 'actualCanonicalSha256', 'equal'], 'comparison');
    id(c.slotID, 'comparison.slotID'); digest(c.expectedCanonicalSha256, 'comparison.expectedCanonicalSha256');
    digest(c.actualCanonicalSha256, 'comparison.actualCanonicalSha256');
    requireThat(typeof c.equal === 'boolean' && c.equal === (c.expectedCanonicalSha256 === c.actualCanonicalSha256),
      'comparison.equal', 'comparison contradicts canonical digests');
    const want = e.expectedOutputs.find(v => v.slotID === c.slotID);
    const got = e.actualOutputs.find(v => v.slotID === c.slotID);
    requireThat(want.mediaType === 'application/json' && got.mediaType === 'application/json',
      'comparison', 'JSON comparator requires JSON outputs');
    if (want.sha256 === got.sha256) requireThat(c.equal && want.byteLength === got.byteLength,
      'comparison', 'identical raw digests cannot declare differing JSON or sizes');
  }
  requireThat((status === 'EXECUTED_MATCH') === e.comparisons.every(v => v.equal),
    'checkResult.status', 'status contradicts comparison results');
  return e;
}
function bindExecution(e, check, data, caseID) {
  requireThat(canonicalJson(e.processRef) === canonicalJson(check.processRef),
    'execution.processRef', 'process differs from requested check', 'CHECK_PLAN_MISMATCH');
  for (const [field, value] of [['inputBindings', check.inputBindings], ['expectedOutputs', check.expectedOutputs],
    ['environment', check.requiredEnvironment], ['parameters', data.parameters]]) {
    requireThat(canonicalJson(e[field]) === canonicalJson(value), `execution.${field}`,
      'execution basis differs from the sealed procedure', 'CHECK_PLAN_MISMATCH');
  }
  requireThat(data.methodSpec.mode === 'TOOL' && data.methodSpec.executableDigest.status === 'VALUE' &&
    e.toolDigest === data.methodSpec.executableDigest.value && e.comparator === check.comparator,
    'execution.toolDigest', 'tool or comparator differs from the sealed procedure', 'CHECK_PLAN_MISMATCH');
  return e;
}

function observationBody(value, caseID) {
  id(caseID, 'caseID'); plain(value, 'observation');
  const common = ['intendedRequestRef', 'attemptID', 'mode', 'checkpointHistory', 'limitations'];
  requireThat(['CHECKS', 'REJECTED_INPUT'].includes(value.mode), 'observation.mode', 'unsupported mode');
  const extra = value.mode === 'CHECKS'
    ? ['packageRef', 'manifestHash', 'binding', 'context', 'materialResults', 'checkResults']
    : ['receivedDigest', 'digestKind', 'failureCodes', 'declaredMetadata'];
  shape(value, [...common, ...extra], 'observation');
  recordRefKind(value.intendedRequestRef, caseID, 'REVIEW_REQUEST', 'observation.intendedRequestRef');
  id(value.attemptID, 'observation.attemptID');
  assertCheckpoint(value.checkpointHistory); strings(value.limitations, 'observation.limitations');
  if (value.mode === 'CHECKS') {
    recordRefKind(value.packageRef, caseID, 'PACKAGE_RECORD', 'observation.packageRef');
    digest(value.manifestHash, 'observation.manifestHash');
    requireThat(value.binding === 'MATCH', 'observation.binding', 'CHECKS requires MATCH binding');
    requireThat(['SATISFIED', 'UNSATISFIED', 'NOT_ASSESSABLE'].includes(value.context),
      'observation.context', 'unsupported context result');
    list(value.materialResults, 'observation.materialResults');
    for (const result of value.materialResults) {
      shape(result, ['blobRef', 'status', 'reason'], 'materialResult');
      assertBlobRef(result.blobRef, caseID);
      requireThat(['HASH_MATCH', 'HASH_MISMATCH', 'NOT_OBTAINED', 'NOT_CHECKED'].includes(result.status),
        'materialResult.status', 'unsupported material result');
      text(result.reason, 'materialResult.reason');
    }
    uniqueBy(value.materialResults, 'observation.materialResults', value =>
      canonicalJson([value.blobRef.ownerVersionRef.caseID, value.blobRef.ownerVersionRef.objectID,
        value.blobRef.ownerVersionRef.version, value.blobRef.slotID]));
    value.materialResults.sort((a, b) => compareCanonical(a.blobRef, b.blobRef));
    list(value.checkResults, 'observation.checkResults');
    requireThat(value.checkResults.length <= 100, 'observation.checkResults', 'at most 100 check results');
    for (const result of value.checkResults) {
      const executed = result.status !== 'NOT_RUN';
      shape(result, executed ? ['checkID', 'status', 'reason', 'execution'] : ['checkID', 'status', 'reason'], 'checkResult');
      id(result.checkID, 'checkResult.checkID'); text(result.reason, 'checkResult.reason');
      requireThat(['NOT_RUN', 'EXECUTED_MATCH', 'EXECUTED_MISMATCH', 'EXECUTION_ERROR'].includes(result.status),
        'checkResult.status', 'unsupported procedure result');
      if (executed) validateExecution(result.execution, result.status, caseID);
    }
    uniqueBy(value.checkResults, 'observation.checkResults', value => value.checkID);
    value.checkResults.sort((a, b) => compareCanonical(a.checkID, b.checkID));
  } else {
    digest(value.receivedDigest, 'observation.receivedDigest');
    requireThat(['CANONICAL_MANIFEST', 'RAW_INPUT'].includes(value.digestKind),
      'observation.digestKind', 'unsupported digest kind');
    list(value.failureCodes, 'observation.failureCodes', 1);
    value.failureCodes.forEach(code => id(code, 'observation.failureCodes'));
    value.failureCodes = [...new Set(value.failureCodes)].sort();
    plain(value.declaredMetadata, 'observation.declaredMetadata');
  }
  // Context and material results are attributed reviewer assertions. Chaincode
  // cannot establish their truth merely by accepting this record.
  return value;
}
function validateObservationInput(rawObject) {
  const value = cloneJson(rawObject); operationInput(value, 'observation');
  observationBody(value.observation, value.caseID); return value;
}
function validateObservationBody(body, caseID) { return observationBody(cloneJson(body), caseID); }

/** Bind an observation to requested checks, without asserting execution. */
function validateObservationBinding(observation, request, caseID) {
  const observed = validateObservationBody(observation, caseID);
  const requested = validateReviewBody(request, caseID);
  if (observed.mode === 'CHECKS') {
    requireThat(observed.checkpointHistory.channelID === requested.checkpointBasis.channelID,
      'observation.checkpointHistory.channelID', 'history channel differs from basis channel', 'CHECKPOINT_MISMATCH');
    requireThat(BigInt(observed.checkpointHistory.blockNumber) > BigInt(requested.checkpointBasis.blockNumber),
      'observation.checkpointHistory.blockNumber', 'history must follow the basis checkpoint', 'CHECKPOINT_MISMATCH');
    const expected = requested.checkPlan.map(check => check.checkID).sort();
    const actual = observed.checkResults.map(check => check.checkID).sort();
    requireThat(canonicalJson(actual) === canonicalJson(expected), 'observation.checkResults',
      'one result per requested check is required', 'CHECK_PLAN_MISMATCH');
  }
  return observed;
}

const REVIEW_POLICY_DEFINITION = {
  profileKind: 'POLICY', profileID: 'pi0-m2', version: 5, schemaVersion: SCHEMA_VERSION,
  stage: 'M3_ISSUES_AND_HISTORY',
  supportedRecordKinds: ['CASE_CONFIG', 'MATERIAL_VERSION', 'REVIEW_REQUEST', 'PACKAGE_RECORD', 'OBSERVATION', 'ISSUE', 'ISSUE_RESPONSE', 'ISSUE_DISPOSITION'],
  bodySchemas: {
    review: ['targetRef', 'reviewerActorRef', 'scope', 'checkpointBasis', 'policyRef',
      'verifierSpecRef', 'checkPlan', 'predecessorRequestRef'],
    package: ['requestRef', 'manifestHash', 'formatVersion', 'declaredExporter'],
    observationCommon: ['intendedRequestRef', 'attemptID', 'mode', 'checkpointHistory', 'limitations'],
    observationChecks: ['packageRef', 'manifestHash', 'binding', 'context', 'materialResults', 'checkResults'],
    observationRejectedInput: ['receivedDigest', 'digestKind', 'failureCodes', 'declaredMetadata'],
    issue: ['issueType', 'targetRef', 'reasonCode', 'rationale', 'supportRefs', 'associatedRequestRef'],
    issueResponse: ['issueRef', 'statement', 'supportRefs', 'issueSeq', 'previousEventRef'],
    issueDisposition: ['issueRef', 'expectedIssueSeq', 'disposition', 'rationale', 'supportRefs', 'issueSeq', 'previousEventRef'],
  },
  rules: {
    scope: 'TARGET_FINDING_OR_REPORT_PLUS_EXPLICIT_EXTRA_ROOTS_AND_SEALED_BASIS',
    expected: 'CASE_CONFIG_MATERIAL_BASIS_ISSUES_AND_EVENTS_AT_CHI_ALL_CASE_PROFILES',
    authority: 'ASSURANCE_REVIEWER_OPENS_DESIGNATED_INDEPENDENT_REVIEWER_NOT_BASIS_AUTHOR',
    packageAuthority: 'CASE_FORENSIC_INVESTIGATOR_OR_DESIGNATED_INDEPENDENT_REVIEWER',
    observationAuthority: 'DESIGNATED_INDEPENDENT_REVIEWER_ONLY',
    checkpoint: 'BASIS_PRECEDES_REQUEST_HISTORY_INCLUDES_REQUEST_AND_OBSERVED_PACKAGE',
    checkPlan: 'OPTIONAL_UNIQUE_RERUN_PROCESS_CHECKS_EXACT_TOOL_INPUTS_OUTPUTS_ENVIRONMENT',
    comparator: 'JSON_CANONICAL_EQUAL',
    procedureResult: 'ATTRIBUTED_EXECUTION_EVIDENCE_MATCH_MISMATCH_ERROR_OR_NOT_RUN',
    materialResult: 'HASH_MATCH_HASH_MISMATCH_NOT_OBTAINED_NOT_CHECKED_WITH_REASON',
    contextResult: 'SATISFIED_UNSATISFIED_NOT_ASSESSABLE_ATTRIBUTED_REVIEWER_ASSERTION',
    rejectedInput: 'EXISTING_REQUEST_UNIQUE_REVIEWER_ATTEMPT_ACTUAL_CHANNEL_NO_TRUST_IN_REJECTED_BASIS',
    profileBinding: 'EXACT_KIND_ID_VERSION_DIGEST_AND_CASE_ALLOWLIST',
    declarationBinding: 'REGISTERED_RECORD_VERSION_SLOT_DIGEST_NOT_PROOF_OF_EXECUTION',
    observationCoverage: 'ONE_BOUND_RESULT_PER_REQUESTED_CHECK_NO_MISSING_OR_FOREIGN_CHECK',
    duplicateAttempt: 'ATOMIC_CREATE_ONLY_INDEX_WITH_IDEMPOTENT_OPERATION_RECEIPT',
    unsupportedHistory: 'FAIL_UNSUPPORTED_ON_UNKNOWN_RECORD_KIND',
    issueRelevance: 'EXACT_VERSION_ANCESTOR_AT_CHI_OR_REQUEST_LINKED_THROUGH_KAPPA',
    issueStatus: 'OPEN_ANSWERED_DISPOSITION_WITH_RESPONSE_NOT_AUTOMATIC_CLOSURE',
    contextWithIssues: 'COMPLETE_REGISTERED_CONTEXT_CAN_BE_SATISFIED_WITH_OPEN_CHALLENGE',
    limits: 'BOUNDED_REGISTERED_ISSUES_NO_SUBSTANTIVE_TRUTH_CLAIM',
  },
};
const VERIFIER_SPEC_DEFINITION = {
  profileKind: 'VERIFIER', profileID: 'nu0-m2', version: 5, schemaVersion: SCHEMA_VERSION,
  stage: 'M3_ISSUES_AND_HISTORY',
  packageFormat: 'LWFA_PACKAGE_2',
  rules: {
    authority: 'TRUSTED_PEER_VALIDATION_METADATA_FULL_BLOCK_REPLAY_ONLY_VALID_TRANSACTIONS',
    chronology: 'SEALED_MATERIAL_BIRTH_AT_OR_BEFORE_BASIS_REQUEST_AFTER_BASIS_PACKAGE_AFTER_REQUEST',
    expected: 'INDEPENDENT_LEDGER_CASE_CONFIG_MATERIAL_ISSUES_AND_EVENTS_AT_CHI_ALL_PROFILES',
    omissions: 'NEVER_BACKFILL_MISSING_PACKAGE_METADATA_FROM_LEDGER',
    binding: 'INTENDED_REQUEST_REGISTERED_MANIFEST_TARGET_BASIS_PROFILES_SCOPE_AND_CHECK_PLAN',
    disclosure: 'MISSING_REQUIRED_METADATA_UNSATISFIED_MISSING_BLOB_NOT_OBTAINED',
    history: 'ALL_PACKAGES_OBSERVATIONS_BASIS_AND_LINKED_ISSUES_WITH_EVENTS_THROUGH_CUTOFF',
    checks: 'DOCKER_ALLOWLISTED_SINGLE_BLOB_SINGLE_JSON_OUTPUT_RERUN',
    admissionCompatibility: 'ALPHA0_V5_PI0_M2_V5_NU0_M2_V5_NO_LEGACY_REQUEST_PROMOTION',
    manifestCommitment: 'SHA256_RAW_UTF8_MANIFEST_BYTES_CANONICAL_WRITER_NO_WHITESPACE_NORMALIZATION',
    inventory: 'MANIFEST_AND_DECLARED_FILES_ONLY_NO_SYMLINKS_512_FILES_128_MIB_TOTAL_16_MIB_PER_BLOB',
    rejectionHistory: 'TRUSTED_ACTUAL_CHANNEL_KAPPA_INCLUDES_REQUEST_WITHOUT_TRUSTING_CHI',
    results: 'SEPARATE_BINDING_CONTEXT_REFERENCE_MATERIAL_PROCEDURE_AND_HISTORY_NO_OVERALL_VERIFIED',
    unknownKinds: 'UNSUPPORTED_PROFILE_INSTEAD_OF_SILENT_IGNORE',
    limits: 'BOUNDED_REGISTERED_HISTORY_NO_PROOF_OF_ORIGINAL_EXECUTION_OR_SUBSTANTIVE_TRUTH',
  },
};
function supportedDefinition(bundleKey, expected) {
  const bundled = require('./profiles.json');
  shape(bundled, ['deployment', 'admission', 'reviewPolicy', 'verifierSpec'], 'profiles');
  requireThat(canonicalJson(bundled[bundleKey]) === canonicalJson(expected),
    `profiles.${bundleKey}`, 'bundled definition is not supported by this implementation', 'UNSUPPORTED_PROFILE');
  const definition = cloneJson(expected);
  const ref = { profileKind: definition.profileKind, profileID: definition.profileID,
    version: definition.version, sha256: hashBytes(Buffer.from(canonicalJson(definition), 'utf8')) };
  return { definition, ref };
}
function getReviewProfiles() {
  return { policy: supportedDefinition('reviewPolicy', REVIEW_POLICY_DEFINITION),
    verifier: supportedDefinition('verifierSpec', VERIFIER_SPEC_DEFINITION) };
}
function getSupportedProfiles() {
  const { policy, verifier } = getReviewProfiles();
  return [getAdmissionProfile(), policy, verifier];
}

module.exports = Object.freeze({ SCHEMA_VERSION, LIMITS, HASH_PREFIX, LWFAError,
  parseJson, canonicalJson, hashBytes, hashJson, assertActorRef, assertMaterialRef,
  assertRecordRef, assertProfileRef, assertBlobDescriptor, assertBlobRef,
  assertCheckpoint, assertKnowledge, assertInputBinding, sortMaterialRefs,
  deriveDirectDeps, assertDirectDeps, commitEnvelope, verifyEnvelopeCommitment,
  validateInitializeInput, validateRegisterInput, validateMaterialBody, materialRef,
  recordRef, getAdmissionProfile, validateDeployment, assertID: id, assertExactShape: shape,
  validateReviewInput, validateReviewBody, validatePackageInput, validatePackageBody,
  validateObservationInput, validateObservationBody, validateObservationBinding, validateExecution, bindExecution, getReviewProfiles, getSupportedProfiles });
