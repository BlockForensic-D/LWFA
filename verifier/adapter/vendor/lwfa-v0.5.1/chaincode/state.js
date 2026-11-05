'use strict';

// Transaction-local state handling. A successful simulation/receipt is not a
// Fabric VALID commit: the client must subsequently check commit status.
const model = require('./model');

const ROLES = Object.freeze([
  'AcquisitionOperator', 'ForensicInvestigator',
  'AssuranceReviewer', 'IndependentReviewer',
]);
const STATE_TYPES = Object.freeze([
  'case', 'objectMeta', 'material', 'record', 'caseHead', 'journal',
  'operation', 'issueHead', 'observationAttempt',
]);

function fail(code, path, message) {
  throw new model.LWFAError(code, path, message);
}
function check(condition, code, path, message) {
  if (!condition) fail(code, path, message);
}
function clone(value) {
  return model.parseJson(model.canonicalJson(value));
}
function identifier(value, path) {
  check(typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value),
    'SCHEMA_ERROR', path, 'invalid identifier');
}
function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

/** Authenticate the certificate identity and its deployment-approved role. */
function authenticate(ctx, deployment) {
  try {
    const cid = ctx.clientIdentity;
    const actor = { mspID: cid.getMSPID(), clientID: cid.getID() };
    model.assertActorRef(actor);
    check(deployment && typeof deployment.roleAttribute === 'string'
      && deployment.roleAttribute.length > 0, 'UNAUTHORIZED', 'deployment',
    'deployment role policy is required');
    const role = cid.getAttributeValue(deployment.roleAttribute);
    check(ROLES.includes(role), 'UNAUTHORIZED', 'identity.role',
      'an approved certificate role is required');
    check(deployment.roleMSPs
      && Object.prototype.hasOwnProperty.call(deployment.roleMSPs, role)
      && Array.isArray(deployment.roleMSPs[role])
      && deployment.roleMSPs[role].includes(actor.mspID),
    'UNAUTHORIZED', 'identity.mspID', 'MSP is not approved for this role');
    return { actor: clone(actor), role };
  } catch (error) {
    if (error instanceof model.LWFAError && error.code === 'UNAUTHORIZED') throw error;
    fail('UNAUTHORIZED', 'identity', 'missing or invalid authenticated identity');
  }
}

function actorEquals(a, b) {
  model.assertActorRef(a);
  model.assertActorRef(b);
  return model.canonicalJson(a) === model.canonicalJson(b);
}

/** A valid deployment identity also needs an exact actor assignment in case. */
function requireCaseMember(config, identity, allowedRoles) {
  try {
    model.assertActorRef(identity.actor);
    check(ROLES.includes(identity.role), 'UNAUTHORIZED', 'identity.role',
      'invalid authenticated role');
    check(config && Array.isArray(config.members), 'UNAUTHORIZED', 'case.members',
      'case membership is unavailable');
    const matches = config.members.filter(member => member && actorEquals(member.actor, identity.actor));
    check(matches.length === 1, 'UNAUTHORIZED', 'case.members',
      'one exact case membership is required');
    const member = matches[0];
    check(Array.isArray(member.roles) && member.roles.includes(identity.role),
      'UNAUTHORIZED', 'case.member.roles', 'authenticated role is not assigned to actor in case');
    if (allowedRoles !== undefined) {
      check(Array.isArray(allowedRoles) && allowedRoles.every(role => ROLES.includes(role))
        && allowedRoles.includes(identity.role), 'UNAUTHORIZED', 'operation.role',
      'authenticated case role cannot perform this operation');
    }
    return clone(member);
  } catch (error) {
    if (error instanceof model.LWFAError && error.code === 'UNAUTHORIZED') throw error;
    fail('UNAUTHORIZED', 'case.members', 'invalid case membership or identity');
  }
}

function stateKey(ctx, type, ...attributes) {
  check(STATE_TYPES.includes(type), 'STATE_KEY_ERROR', 'state.type', 'unknown state namespace');
  check(attributes.length > 0 && attributes.every(attribute => typeof attribute === 'string'
    && attribute.length > 0 && !/[\u0000\u{10ffff}]/u.test(attribute)),
  'STATE_KEY_ERROR', 'state.attributes', 'nonempty valid composite-key attributes required');
  // The JSON profile rejects malformed surrogate pairs before key construction.
  model.canonicalJson(attributes);
  return ctx.stub.createCompositeKey(`lwfa.${type}`, attributes);
}

function sequenceKey(sequence) {
  check(Number.isInteger(sequence) && sequence >= 1 && sequence <= model.LIMITS.version,
    'SCHEMA_ERROR', 'sequence', 'sequence is outside the supported positive range');
  return String(sequence).padStart(10, '0');
}

/**
 * Explicit transaction-local reads and staged writes. Fabric GetState does not
 * read back prior PutState writes; local staged values provide that behavior.
 * Stage reads each key before writing to establish its MVCC read dependency.
 */
class UnitOfWork {
  constructor(ctx) {
    this.ctx = ctx;
    this.cache = new Map();
    this.staged = new Map();
    this.closed = false;
  }

  assertOpen() {
    check(!this.closed, 'UOW_CLOSED', 'state', 'transaction unit has already been flushed');
  }

  key(type, attributes) {
    check(Array.isArray(attributes), 'STATE_KEY_ERROR', 'state.attributes', 'attribute array required');
    return stateKey(this.ctx, type, ...attributes);
  }

  async read(type, attributes) {
    this.assertOpen();
    const key = this.key(type, attributes);
    if (this.staged.has(key)) return clone(this.staged.get(key).value);
    if (this.cache.has(key)) return clone(this.cache.get(key));
    const bytes = await this.ctx.stub.getState(key);
    if (!bytes || bytes.length === 0) {
      this.cache.set(key, null);
      return null;
    }
    let value;
    try {
      check(bytes instanceof Uint8Array, 'STATE_CORRUPT', key, 'state must contain bytes');
      const buffer = Buffer.from(bytes);
      const source = buffer.toString('utf8');
      check(Buffer.from(source, 'utf8').equals(buffer), 'STATE_CORRUPT', key, 'invalid UTF-8 state');
      value = model.parseJson(source);
      check(value !== null, 'STATE_CORRUPT', key, 'null is reserved for absent state');
      value = clone(value);
    } catch (error) {
      if (error instanceof model.LWFAError && error.code === 'STATE_CORRUPT') throw error;
      fail('STATE_CORRUPT', key, 'state does not satisfy the LWFA JSON profile');
    }
    this.cache.set(key, value);
    return clone(value);
  }

  async stage(type, attributes, value, { createOnly = false } = {}) {
    this.assertOpen();
    check(typeof createOnly === 'boolean', 'SCHEMA_ERROR', 'createOnly', 'boolean required');
    check(value !== null, 'SCHEMA_ERROR', 'state.value', 'null is reserved for absent state');
    const encoded = model.canonicalJson(value);
    const copy = model.parseJson(encoded);
    const key = this.key(type, attributes);
    const previous = await this.read(type, attributes);
    check(!createOnly || previous === null, 'DUPLICATE_ID', key, 'state identifier already exists');
    this.staged.set(key, { value: copy, encoded });
  }

  async flush() {
    this.assertOpen();
    // All serialization and validation precede the first PutState. Closing even
    // after a write error prevents reuse; Fabric controls transaction atomicity.
    const writes = [...this.staged.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, entry]) => [key, Buffer.from(entry.encoded, 'utf8')]);
    this.closed = true;
    for (const [key, bytes] of writes) await this.ctx.stub.putState(key, bytes);
  }
}

function receiptArguments(caseID, actor, operationID, inputHash, operationName) {
  identifier(caseID, 'caseID');
  model.assertActorRef(actor);
  identifier(operationID, 'operationID');
  identifier(operationName, 'operationName');
  check(typeof inputHash === 'string' && /^[a-f0-9]{64}$/.test(inputHash),
    'SCHEMA_ERROR', 'inputHash', 'lowercase SHA-256 digest required');
}

function assertReceipt(receipt) {
  try {
    check(exactKeys(receipt, ['schemaVersion', 'caseID', 'actor', 'operationID',
      'operationName', 'inputHash', 'resultRef', 'caseSeq', 'txID']),
    'STATE_CORRUPT', 'receipt', 'invalid receipt fields');
    check(receipt.schemaVersion === model.SCHEMA_VERSION,
      'STATE_CORRUPT', 'receipt.schemaVersion', 'unsupported receipt schema');
    receiptArguments(receipt.caseID, receipt.actor, receipt.operationID,
      receipt.inputHash, receipt.operationName);
    model.assertRecordRef(receipt.resultRef, receipt.caseID);
    sequenceKey(receipt.caseSeq);
    identifier(receipt.txID, 'receipt.txID');
  } catch (error) {
    if (error instanceof model.LWFAError && error.code === 'STATE_CORRUPT') throw error;
    fail('STATE_CORRUPT', 'receipt', 'stored receipt is malformed');
  }
}

/** Receipt lookup after authentication and case access, before mutable business checks. */
async function readReceipt(uow, caseID, actor, operationID, inputHash, operationName) {
  receiptArguments(caseID, actor, operationID, inputHash, operationName);
  const receipt = await uow.read('operation', [caseID, actor.mspID, actor.clientID, operationID]);
  if (receipt === null) return null;
  assertReceipt(receipt);
  check(receipt.caseID === caseID && actorEquals(receipt.actor, actor)
    && receipt.operationID === operationID && receipt.operationName === operationName
    && receipt.inputHash === inputHash, 'IDEMPOTENCY_CONFLICT', 'operationID',
  'operation identity was already used for different input or operation');
  return clone(receipt);
}

/** Stages the head, immutable journal event, and immutable receipt without flushing writes. */
async function stageMutation(uow, { caseID, actor, operationID, operationName,
  inputHash, resultRef, recordID, txID, initialize = false }) {
  receiptArguments(caseID, actor, operationID, inputHash, operationName);
  model.assertRecordRef(resultRef, caseID);
  identifier(recordID, 'recordID');
  identifier(txID, 'txID');
  check(recordID === resultRef.recordID, 'SCHEMA_ERROR', 'recordID',
    'recordID must identify resultRef');
  check(typeof initialize === 'boolean', 'SCHEMA_ERROR', 'initialize', 'boolean required');
  const head = await uow.read('caseHead', [caseID]);
  let sequence;
  if (initialize) {
    check(head === null, 'DUPLICATE_ID', 'caseHead', 'case sequence already exists');
    sequence = 1;
  } else {
    check(exactKeys(head, ['caseID', 'sequence']) && head.caseID === caseID
      && Number.isInteger(head.sequence) && head.sequence >= 1
      && head.sequence <= model.LIMITS.version, 'STATE_CORRUPT', 'caseHead',
    'existing case sequence is missing or malformed');
    check(head.sequence < model.LIMITS.version, 'LIMIT_EXCEEDED', 'caseHead.sequence',
      'case sequence exhausted');
    sequence = head.sequence + 1;
  }
  const receipt = {
    schemaVersion: model.SCHEMA_VERSION, caseID, actor: clone(actor), operationID,
    operationName, inputHash, resultRef: clone(resultRef), caseSeq: sequence, txID,
  };
  assertReceipt(receipt);
  await uow.stage('caseHead', [caseID], { caseID, sequence }, { createOnly: initialize });
  await uow.stage('journal', [caseID, sequenceKey(sequence)], {
    caseID, sequence, actor: clone(actor), operationID, operationName,
    recordRef: clone(resultRef), txID,
  }, { createOnly: true });
  await uow.stage('operation', [caseID, actor.mspID, actor.clientID, operationID],
    receipt, { createOnly: true });
  return clone(receipt);
}

module.exports = Object.freeze({ authenticate, requireCaseMember, actorEquals,
  stateKey, sequenceKey, UnitOfWork, readReceipt, stageMutation, validateReceipt: assertReceipt });
