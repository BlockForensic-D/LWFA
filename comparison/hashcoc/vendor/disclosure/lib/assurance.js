'use strict';
// The entrypoint for the v070 research protocol. Calling the old package
// verifier alone still means the original v0.5.1 protocol, never this protocol.
const core = require('./core');
const {m, same} = core.req('client/io');
const P = core.req('client/package');
const D = require('./disclosure');
const {validateCheckpoint} = require('./checkpoint');

function assessResearchPackage(options) {
  const {snapshot, request, identities, expectedCheckpoint, actualChannel,
    packageDir, packageRecord, presentedDisclosure} = options;
  const anchor = validateCheckpoint(snapshot, expectedCheckpoint, actualChannel);
  if (options.historyCheckpoint && !same(options.historyCheckpoint, anchor.checkpoint))
    throw new Error('ASSESSMENT_HISTORY_CHECKPOINT_MISMATCH');
  const args = {snapshot, request, identities, historyCheckpoint: anchor.checkpoint};
  const disclosure = D.assess(args);
  let packageResult = {binding:'NOT_EVALUATED', context:'NOT_EVALUATED', materialResults:[],
    reason:'A snapshot does not show which package bytes were presented to this verifier.'};
  if (Boolean(packageDir) !== Boolean(packageRecord)) throw new Error('PACKAGE_DIRECTORY_AND_RECORD_REQUIRED_TOGETHER');
  if (packageDir) {
    const assessment = P.assessPackage(packageDir, request, packageRecord, snapshot, anchor.checkpoint);
    // Serialized output excludes executable bytes and maps and does not attest to tool execution.
    packageResult = Object.fromEntries(['binding','context','contextMeaning','materialResults',
      'reason','failureCodes','observationMode','contextFailure','meaning'].filter(k=>k in assessment)
      .map(k=>[k,assessment[k]]));
  }
  const presentedCheck = presentedDisclosure === undefined
    ? {status:'NOT_PRESENTED', meaning:'Canonical disclosure computed from the independently anchored snapshot.'}
    : D.verifyPresentedDisclosure(presentedDisclosure, args);
  return {
    format:'LWFA_RESEARCH_ASSESSMENT_070',
    protocol:'LWFA_EXTERNAL_ASSURANCE_2',
    disclosurePolicyRef:disclosure.policyRef,
    requestRef:m.recordRef(request),
    checkpoint:anchor.checkpoint,
    checkpointTrust:anchor,
    originalReviewPolicyRef:request.body.policyRef,
    originalVerifierSpecRef:request.body.verifierSpecRef,
    packageAssessment:packageResult,
    disclosure,
    presentedDisclosureCheck:presentedCheck,
    procedure:{status:'NOT_RUN', reason:'This entrypoint verifies context and commitments; it does not execute the declared forensic procedure.'},
    interpretation:'Package context is relative to its sealed chi. Interpret it together with this mandatory disclosure, creator binding and scoped authority replay. Open concerns do not mean coverage is incomplete. No substantive truth or legal admissibility verdict is produced.'
  };
}
module.exports = {assessResearchPackage};
