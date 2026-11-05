'use strict';
// Transaction-creator extraction from blocks already fetched for history replay.
// Trust model is unchanged from lwfa-v0.5.1/client/history.js: validation flags come
// from the TLS-authenticated Org3 peer. A VALID flag means that peer accepted the
// creator signature and MSP membership at commit; this module does not re-verify them.
const path = require('node:path');
const { createRequire } = require('node:module');
const core = require('./core');
const H = core.req('client/history');

const utf8 = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
const ENDORSER_TRANSACTION = 3;

/**
 * Map txID -> {mspid, idBytes, block, index} for VALID endorser transactions.
 * Blocks must be the same ordered block list given to history.replay().
 */
function extractCreators(blocks, channel) {
  const out = new Map();
  blocks.forEach(raw => {
    // decodeBlock re-checks the data hash and channel of every valid envelope.
    const decoded = H.decodeBlock(raw, channel, '\u0000lwfa-disclosure-no-namespace');
    const root = H.fields(raw);
    const envelopes = H.many(H.msg(root, 2), 1);
    const flags = H.many(H.msg(root, 3), 1)[2];
    envelopes.forEach((env, index) => {
      if (flags[index] !== 0) return;
      const payload = H.msg(H.fields(env), 1);
      const header = H.msg(payload, 1);
      const channelHeader = H.fields(H.one(header, 1));
      const type = Number(H.one(channelHeader, 1, 0, true));
      if (type !== ENDORSER_TRANSACTION) return;
      const txID = utf8(H.one(channelHeader, 5, 2, true));
      if (!txID) throw new Error('CREATOR_TXID_MISSING');
      if (out.has(txID)) throw new Error('DUPLICATE_VALID_TXID');
      const signatureHeader = H.fields(H.one(header, 2));
      const identity = H.fields(H.one(signatureHeader, 1));
      out.set(txID, { mspid: utf8(H.one(identity, 1)), idBytes: Buffer.from(H.one(identity, 2)),
        block: decoded.number, index });
    });
  });
  return out;
}

let shim;
let shimError = null;
function loadShim() {
  if (shim !== undefined) return shim;
  // Same library/version as the chaincode (fabric-shim 2.5.8), so clientID strings
  // are derived exactly as ctx.clientIdentity.getID() derived them at endorsement.
  // fabric-shim installs winston process handlers that can suppress verifier errors.
  // Handlers introduced by the import are removed to preserve error propagation.
  const events = ['uncaughtException', 'unhandledRejection', 'uncaughtExceptionMonitor'];
  const before = Object.fromEntries(events.map(e => [e, new Set(process.listeners(e))]));
  try { shim = createRequire(path.join(__dirname, '..', 'package.json'))('fabric-shim'); }
  catch (error) { shim = null; shimError = String(error.message); }
  for (const e of events) for (const fn of process.listeners(e)) if (!before[e].has(fn)) process.removeListener(e, fn);
  return shim;
}
function identityOf(creator, roleAttribute = 'lwfa.role') {
  const s = loadShim();
  if (!s) return { status: 'IDENTITY_LIBRARY_UNAVAILABLE', error: shimError };
  try {
    const ci = new s.ClientIdentity({ getChannelID: () => 'lwfa-disclosure', getTxID: () => 'lwfa-disclosure',
      getCreator: () => ({ mspid: creator.mspid, idBytes: creator.idBytes }) });
    return { status: 'DERIVED', actor: { mspID: ci.getMSPID(), clientID: ci.getID() },
      // Missing role is deliberately retained as null: authority replay must reject
      // it instead of substituting a role from the case configuration.
      role: ci.getAttributeValue(roleAttribute) ?? null };
  } catch (error) {
    return { status: 'CREATOR_UNPARSEABLE', error: String(error.message) };
  }
}
/** txID -> {status, actor, role, block, index}. */
function identities(blocks, channel, roleAttribute) {
  const out = new Map();
  for (const [txID, creator] of extractCreators(blocks, channel))
    out.set(txID, { ...identityOf(creator, roleAttribute), block: creator.block, index: creator.index });
  return out;
}

module.exports = { extractCreators, identityOf, identities, shimAvailable: () => Boolean(loadShim()) };
