'use strict';
// An external, mandatory disclosure protocol. It does not promote v5 on-ledger
// profiles to a new meaning; the legacy request keeps its original policy refs.
const m = require('./core').req('chaincode/model');
const DEFINITION = Object.freeze({
  protocolID: 'LWFA_EXTERNAL_DISCLOSURE', version: '2.0',
  legacy: 'NU0_M2_V5_RESULTS_RETAIN_ORIGINAL_MEANING',
  basis: 'EXACT_TARGET_AND_DIRECT_DEPENDENCY_CLOSURE_AT_CHI',
  currentIssues: 'ALL_EXACT_BASIS_ISSUES_AND_EVENTS_THROUGH_KAPPA',
  earlierVersions: 'ALL_EARLIER_VERSIONS_SAME_CASE_AND_OBJECT_WITH_ISSUES_THROUGH_KAPPA',
  earlierVersionMeaning: 'MANDATORY_DISCLOSURE_ADVISORY_APPLICABILITY_NOT_AUTOMATIC',
  previousReviews: 'ALL_PRIOR_REQUESTS_SAME_EXACT_TARGET_VERSION_WITH_PACKAGES_OBSERVATIONS_LINKED_ISSUES_AND_EVENTS',
  previousReviewMeaning: 'PRESERVE_ORIGINAL_SCOPE_CHI_POLICY_CHECK_PLAN_AND_RECORDED_OUTCOMES_NOT_REEVALUATED',
  coverage: 'RECOMPUTE_EXPECTED_FROM_REVIEWER_TRUSTED_SNAPSHOT_NEVER_FROM_PRESENTED_LIST',
  cutoff: 'KAPPA_EQUALS_SNAPSHOT_ENDPOINT_AND_MUST_BE_PINNED_BY_REVIEWER',
  identity: 'CREATOR_BINDING_AND_BOUNDED_AUTHORITY_REPLAY_SEPARATE_FROM_COVERAGE',
  concerns: 'COMPLETE_DISCLOSURE_MAY_CONTAIN_UNRESOLVED_CHALLENGES',
  claims: 'REGISTERED_SCOPED_HISTORY_ONLY_NO_REAL_WORLD_COMPLETENESS_OR_SUBSTANTIVE_TRUTH',
  limits: {maxCaseRecords: 10000, maxEarlierVersions: 512, maxPriorReviews: 128, maxRequiredRecords: 2048},
});
Object.freeze(DEFINITION.limits);
function getPolicy() {
  const definition = m.parseJson(m.canonicalJson(DEFINITION));
  return {definition, ref: {protocolID: definition.protocolID, version: definition.version,
    sha256: m.hashBytes(Buffer.from(m.canonicalJson(definition), 'utf8'))}};
}
function compose({legacy = {}, disclosure = null, disclosureVerification = null} = {}) {
  // The complete assurance wrapper additionally requires package verification.
  // Here every component stays explicit; concern flags never imply untruth.
  return {protocolRef: getPolicy().ref,
    legacy: {binding: legacy.binding || 'NOT_EVALUATED', context: legacy.context || 'NOT_EVALUATED',
      history: legacy.historyStatus || (typeof legacy.history === 'string' ? legacy.history : 'NOT_EVALUATED')},
    disclosure: {coverage: disclosureVerification?.coverageStatus || disclosure?.coverage?.status || 'NOT_EVALUATED',
      presentedOutputVerification: disclosureVerification ? disclosureVerification.coverageStatus : 'NOT_EVALUATED',
      creatorBinding: disclosure?.creatorBinding?.status || 'NOT_EVALUATED',
      authority: disclosure?.authority?.status || 'NOT_EVALUATED',
      concernFlags: disclosure?.flags || []},
    substantiveTruth: 'NOT_EVALUATED', legacyPolicyUnchanged: true};
}
module.exports = {DEFINITION, getPolicy, compose};
