'use strict';
// Bounded application-authorization replay. This is not signature/MSP/consensus
// revalidation and cannot establish resistance to an adversarial endorsement quorum.
const core = require('./core');
const { same } = core.req('client/io');
const DEPLOYMENT = core.req('chaincode/profiles.json').deployment;
const ROLES = Object.freeze(Object.keys(DEPLOYMENT.roleMSPs));
function position(snapshot, id) {
  const p = snapshot.births.get(id);
  if (!p || !/^(0|[1-9][0-9]*)$/.test(p.block) || !Number.isInteger(p.index) || p.index < 0)
    throw new Error(`MISSING_RECORD_BIRTH:${id}`);
  return p;
}
function prior(snapshot, earlier, later) {
  const a = position(snapshot, earlier.recordID), b = position(snapshot, later.recordID);
  return BigInt(a.block) < BigInt(b.block) || (a.block === b.block && a.index < b.index);
}

function authorityReplay(snapshot, identities, scope, atKappa) {
  const configs = [...atKappa.values()].filter(e => e.kind === 'CASE_CONFIG');
  if (configs.length !== 1) throw new Error('CASE_CONFIG_COVERAGE');
  const config = configs[0].body, violations = [], incomplete = [];
  let checkedRecords = 0;
  const member = actor => config.members.filter(x => same(x.actor, actor));
  const material = (ref, atRecord) => {
    const e = [...atKappa.values()].find(x => x.kind === 'MATERIAL_VERSION' && x.body.objectID === ref.objectID && x.body.version === ref.version);
    return e && e.commitment === ref.commitment && (!atRecord || prior(snapshot, e, atRecord)) ? e : null;
  };
  const owner = objectID => [...atKappa.values()].find(x => x.kind === 'MATERIAL_VERSION' && x.body.objectID === objectID && x.body.version === 1)?.actor ?? null;
  const request = (ref, atRecord) => { const e = atKappa.get(ref.recordID); return e && e.kind === 'REVIEW_REQUEST' && e.commitment === ref.commitment && (!atRecord || prior(snapshot, e, atRecord)) ? e : null; };
  const reviewers = config.reviewers || [];

  for (const e of scope) {
    const p = position(snapshot, e.recordID), id = identities?.get(p.txID);
    const fail = rule => violations.push({ recordID: e.recordID, kind: e.kind, rule, roleSource: 'CERTIFICATE_ATTRIBUTE' });
    if (!id || id.status !== 'DERIVED') {
      incomplete.push({recordID: e.recordID, kind: e.kind, reason: id?.status || 'CREATOR_MISSING'});
      continue;
    }
    checkedRecords += 1;
    if (id.block !== undefined && (String(id.block) !== p.block || id.index !== p.index)) {
      fail('CREATOR_POSITION_MISMATCH'); continue;
    }
    if (!same(id.actor, e.actor)) { fail('ACTOR_CREATOR_MISMATCH'); continue; }
    const certRole = id.role;
    // A parsed certificate without the required role is contrary evidence, not
    // unavailable evidence. Case membership cannot supply this missing credential.
    if (!ROLES.includes(certRole)) { fail('CERTIFICATE_ROLE_MISSING_OR_INVALID'); continue; }
    if (!(DEPLOYMENT.roleMSPs[certRole] || []).includes(id.actor.mspID)) {
      fail('CERTIFICATE_ROLE_MSP_MISMATCH'); continue;
    }
    const cfg = e.kind === 'CASE_CONFIG' ? e.body : config;
    const mem = cfg.members.filter(x => same(x.actor, id.actor));
    if (mem.length !== 1) { fail('EXACT_CASE_MEMBERSHIP'); continue; }
    if (!mem[0].roles.includes(certRole)) { fail('CERTIFICATE_ROLE_NOT_ASSIGNED'); continue; }
    if (e.kind !== 'CASE_CONFIG' && !prior(snapshot, configs[0], e)) {
      fail('CASE_CONFIG_NOT_PRIOR_TO_RECORD'); continue;
    }
    const usable = [certRole];
    const can = roles => usable.some(r => roles.includes(r));
    const b = e.body;
    switch (e.kind) {
      case 'CASE_CONFIG':
        if (!can(['AssuranceReviewer'])) fail('INITIALIZE_REQUIRES_ASSURANCE_REVIEWER');
        if (config.members.some(member => member.roles.some(role => !(DEPLOYMENT.roleMSPs[role] || []).includes(member.actor.mspID))))
          fail('CASE_MEMBER_ROLE_MSP_MISMATCH');
        break;
      case 'MATERIAL_VERSION': {
        if (!can(['AcquisitionOperator', 'ForensicInvestigator'])) { fail('MATERIAL_ROLE'); break; }
        if (!can(['ForensicInvestigator']) && !['CONTEXT', 'ARTIFACT'].includes(b.materialType)) fail('ACQUISITION_OPERATOR_TYPE_LIMIT');
        if (b.version > 1 && !same(owner(b.objectID), e.actor) && !(can(['ForensicInvestigator']) && same(config.leadInvestigator, e.actor)))
          fail('REVISION_REQUIRES_OWNER_OR_LEAD');
        break;
      }
      case 'REVIEW_REQUEST': {
        if (!can(['AssuranceReviewer'])) fail('OPEN_REVIEW_ROLE');
        const target = material(b.targetRef, e);
        if (!target) fail('REQUEST_TARGET_NOT_COMMITTED');
        else if (same(target.actor, b.reviewerActorRef)) fail('REVIEWER_IS_TARGET_AUTHOR');
        const rm = member(b.reviewerActorRef);
        if (rm.length !== 1 || !rm[0].roles.includes('IndependentReviewer') || !reviewers.some(a => same(a, b.reviewerActorRef)))
          fail('REVIEWER_NOT_ASSIGNED');
        break;
      }
      case 'PACKAGE_RECORD': {
        const r = request(b.requestRef, e);
        if (!r) { fail('PACKAGE_REQUEST_NOT_COMMITTED'); break; }
        if (!(can(['ForensicInvestigator']) || (can(['IndependentReviewer']) && same(e.actor, r.body.reviewerActorRef)))) fail('PACKAGE_REGISTRAR');
        break;
      }
      case 'OBSERVATION': {
        const r = request(b.intendedRequestRef, e);
        if (!r) { fail('OBSERVATION_REQUEST_NOT_COMMITTED'); break; }
        if (!can(['IndependentReviewer']) || !same(e.actor, r.body.reviewerActorRef)) fail('OBSERVATION_REQUIRES_DESIGNATED_REVIEWER');
        break;
      }
      case 'ISSUE': break; // any exact case member
      case 'ISSUE_RESPONSE':
      case 'ISSUE_DISPOSITION': {
        const issue = atKappa.get(b.issueRef.recordID);
        if (!issue || issue.kind !== 'ISSUE' || issue.commitment !== b.issueRef.commitment || !prior(snapshot, issue, e)) { fail('ISSUE_NOT_COMMITTED'); break; }
        const tref = issue.body.targetRef, isRequest = !Object.hasOwn(tref, 'objectID');
        const target = isRequest ? request(tref, issue) : material(tref, issue);
        if (!target) { fail('ISSUE_TARGET_NOT_COMMITTED'); break; }
        if (e.kind === 'ISSUE_RESPONSE') {
          if (isRequest) { if (!can(['AssuranceReviewer']) || !same(e.actor, target.actor)) fail('REQUEST_RESPONSE_REQUIRES_REQUEST_CREATOR'); }
          else if (!can(['AcquisitionOperator', 'ForensicInvestigator']) || !(same(e.actor, target.actor) ||
            same(e.actor, owner(target.body.objectID)) || (can(['ForensicInvestigator']) && same(e.actor, config.leadInvestigator))))
            fail('RESPONSE_REQUIRES_CREATOR_OWNER_OR_LEAD');
          break;
        }
        if (issue.body.issueType !== 'CHALLENGE') { fail('DISPOSITION_ONLY_FOR_CHALLENGE'); break; }
        if (b.disposition === 'WITHDRAWN') { if (!same(e.actor, issue.actor)) fail('WITHDRAWAL_REQUIRES_SUBMITTER'); break; }
        if (!can(['IndependentReviewer']) || !reviewers.some(a => same(a, e.actor))) fail('DISPOSITION_REQUIRES_ASSIGNED_INDEPENDENT_REVIEWER');
        if (same(target.actor, e.actor)) fail('SELF_REVIEW_TARGET_AUTHOR');
        if (!isRequest && same(owner(target.body.objectID), e.actor)) fail('SELF_REVIEW_TARGET_OWNER');
        const linked = isRequest ? tref : issue.body.associatedRequestRef;
        if (linked) { const r = request(linked, issue); if (!r || !same(r.body.reviewerActorRef, e.actor)) fail('LINKED_REQUEST_REVIEWER_REQUIRED'); }
        break;
      }
      default: fail('UNSUPPORTED_RECORD_KIND');
    }
  }
  return { status: violations.length ? 'VIOLATIONS' : !identities ? 'NOT_EVALUATED' : incomplete.length ? 'INCOMPLETE' : 'CONSISTENT',
    roleEvidence: !identities ? 'NO_CERTIFICATE_EVIDENCE' : incomplete.length ? 'PARTIAL_CERTIFICATE_EVIDENCE' :
      violations.some(v => v.rule === 'CERTIFICATE_ROLE_MISSING_OR_INVALID') ? 'CERTIFICATE_ATTRIBUTE_MISSING_OR_INVALID' : 'CERTIFICATE_ATTRIBUTE_ALL',
    scopedRecords: scope.length, checkedRecords, violations, incomplete,
    meaning: 'Selected application authorization rules under the packaged deployment and trusted-peer snapshot; not independent consensus/MSP verification.' };
}


module.exports = { authorityReplay };
