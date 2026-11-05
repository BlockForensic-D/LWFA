'use strict';
// An externally supplied checkpoint is an input trust anchor. This function checks
// agreement; neither a provenance label nor a block hash proves who supplied it.
const core = require('./core');
const {m, same} = core.req('client/io');
function fail(code) { throw new Error(code); }
function checkpointPart(value) {
  if (!value || typeof value !== 'object') fail('EXPECTED_CHECKPOINT_REQUIRED');
  const cp = {channelID:value.channelID, blockNumber:value.blockNumber, blockHeaderHash:value.blockHeaderHash};
  m.assertCheckpoint(cp);
  return cp;
}
function validateCheckpoint(snapshot, expectedCheckpoint, actualChannel) {
  const checkpoint = checkpointPart(expectedCheckpoint);
  const provenance = expectedCheckpoint.provenance;
  if (!provenance || provenance.source !== 'REVIEWER_SUPPLIED' || typeof provenance.reference !== 'string' ||
      !provenance.reference.trim() || provenance.reference.length > 2048) fail('REVIEWER_CHECKPOINT_PROVENANCE_REQUIRED');
  if (actualChannel !== checkpoint.channelID) fail('EXPECTED_CHECKPOINT_CHANNEL_MISMATCH');
  const end = BigInt(checkpoint.blockNumber);
  if (end >= 4096n) fail('REPLAY_BLOCK_LIMIT_4096');
  if (!snapshot || !Array.isArray(snapshot.headers) || snapshot.headers.length !== Number(end) + 1)
    fail('EXPECTED_CHECKPOINT_BLOCK_RANGE_MISMATCH');
  snapshot.headers.forEach((h,i)=>{if(h.number !== String(i))fail('EXPECTED_CHECKPOINT_BLOCK_RANGE_MISMATCH');});
  const last = snapshot.headers.at(-1);
  if (last.number !== checkpoint.blockNumber || last.hash !== checkpoint.blockHeaderHash)
    fail('EXPECTED_CHECKPOINT_HASH_MISMATCH');
  return {checkpoint, provenance:m.parseJson(m.canonicalJson(provenance)),
    anchorMeaning:'Reviewer-supplied checkpoint agreement only. The acquisition source and peer validation metadata remain trusted; signatures/MSP/consensus are not independently revalidated.'};
}
function validateSummary(summary, expectedCheckpoint) {
  if (!summary || !same(checkpointPart(summary.checkpoint), checkpointPart(expectedCheckpoint)))
    fail('SNAPSHOT_SUMMARY_CHECKPOINT_MISMATCH');
}
module.exports = {validateCheckpoint, validateSummary, checkpointPart};
