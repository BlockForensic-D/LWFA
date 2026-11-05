'use strict';

const { Contract, Transaction, Param, Returns } = require('fabric-contract-api');
const m = require('./model');
const s = require('./state');
const issues = require('./issues');

function demand(ok, code, path, message) {
  if (!ok) throw new m.LWFAError(code, path, message);
}
function roleAllowed(identity, roles) {
  demand(roles.includes(identity.role), 'UNAUTHORIZED', 'identity.role', 'operation not allowed for this role');
}
function rawInput(text) { return m.parseJson(text); }
function inputHash(operationName, input, actor) {
  const { schemaVersion, caseID, operationID, ...businessPayload } = input;
  return m.hashJson('OPERATION', { operationName, schemaVersion, caseID, actor, businessPayload });
}
function trustedEnvelope(record, caseID, expectedKind) {
  demand(record !== null, 'NOT_FOUND', 'record', 'record does not exist');
  m.verifyEnvelopeCommitment(record);
  demand(record.caseID === caseID && (!expectedKind || record.kind === expectedKind),
    'STATE_CORRUPT', 'record', 'stored identity or kind does not match its key');
  return record;
}
async function loadCase(uow, caseID) {
  const record = trustedEnvelope(await uow.read('case', [caseID]), caseID, 'CASE_CONFIG');
  const checked = m.validateInitializeInput({ schemaVersion: record.schemaVersion, caseID,
    operationID: 'validate-case', recordID: record.recordID, config: record.body });
  demand(m.canonicalJson(checked.config) === m.canonicalJson(record.body),
    'STATE_CORRUPT', 'case', 'case configuration is not canonical');
  return record;
}
async function loadMaterial(uow, ref, caseID, allowedTypes) {
  m.assertMaterialRef(ref, caseID);
  const stored = await uow.read('material', [caseID, ref.objectID, s.sequenceKey(ref.version)]);
  demand(stored !== null, 'INVALID_REFERENCE', 'materialRef', 'referenced material is not committed');
  const record = trustedEnvelope(stored, caseID, 'MATERIAL_VERSION');
  const body = m.validateMaterialBody(record.body, caseID);
  demand(body.objectID === ref.objectID && body.version === ref.version && record.commitment === ref.commitment,
    'INVALID_REFERENCE', 'materialRef', 'material reference does not match committed content');
  demand(m.canonicalJson(body) === m.canonicalJson(record.body), 'STATE_CORRUPT', 'material', 'noncanonical stored body');
  if (allowedTypes) demand(allowedTypes.includes(body.materialType),
    'INVALID_REFERENCE', 'materialRef', 'referenced producer has an incompatible material type');
  return record;
}
async function loadRecordOfKind(uow, ref, caseID, kind) {
  m.assertRecordRef(ref, caseID);
  demand(ref.kind === kind, 'INVALID_REFERENCE', 'recordRef.kind', 'reference kind mismatch');
  const stored = await uow.read('record', [caseID, ref.recordID]);
  demand(stored !== null, 'INVALID_REFERENCE', 'recordRef', 'referenced record is not committed');
  const record = trustedEnvelope(stored, caseID, kind);
  demand(record.recordID === ref.recordID && record.commitment === ref.commitment,
    'INVALID_REFERENCE', 'recordRef', 'record reference mismatch');
  const validate = kind === 'REVIEW_REQUEST' ? m.validateReviewBody
    : kind === 'PACKAGE_RECORD' ? m.validatePackageBody
    : kind === 'ISSUE' ? issues.validateIssueBody
    : kind === 'ISSUE_RESPONSE' ? (b, c) => issues.validateResponseBody(b, c, true)
    : kind === 'ISSUE_DISPOSITION' ? (b, c) => issues.validateDispositionBody(b, c, true) : null;
  if (validate) demand(m.canonicalJson(validate(record.body, caseID)) === m.canonicalJson(record.body),
    'STATE_CORRUPT', 'record.body', 'stored record body is not canonical');
  return record;
}

async function checkReviewSources(uow, review, caseID) {
  for (const ref of review.scope.extraRoots) await loadMaterial(uow, ref, caseID);
  for (const check of review.checkPlan) {
    const process = await loadMaterial(uow, check.processRef, caseID, ['PROCESS']);
    const data = process.body.data;
    demand(data.methodSpec.mode === 'TOOL', 'INVALID_REFERENCE', 'check.processRef',
      'rerun requires a TOOL process');
    demand(m.canonicalJson(check.inputBindings) === m.canonicalJson(data.inputBindings),
      'CHECK_PLAN_MISMATCH', 'check.inputBindings', 'inputs differ from the sealed process');
    demand(m.canonicalJson(check.expectedOutputs) === m.canonicalJson(data.outputs),
      'CHECK_PLAN_MISMATCH', 'check.expectedOutputs', 'outputs differ from the sealed process');
    demand(m.canonicalJson(check.requiredEnvironment) === m.canonicalJson(data.environment),
      'CHECK_PLAN_MISMATCH', 'check.requiredEnvironment', 'environment differs from the sealed process');
  }
  // Checkpoint membership and scope reachability remain verifier checks.
}

async function checkObservationSources(uow, observation, request, caseID) {
  for (const result of observation.materialResults) {
    const ref = result.blobRef;
    const owner = await loadMaterial(uow, ref.ownerVersionRef, caseID, ['ARTIFACT', 'PROCESS', 'REPORT']);
    const data = owner.body.data;
    const descriptors = owner.body.materialType === 'ARTIFACT' ? [data.blobDescriptor]
      : owner.body.materialType === 'REPORT' ? [data.documentDescriptor] : data.outputs;
    const descriptor = descriptors.find(item => item.slotID === ref.slotID);
    demand(descriptor && descriptor.sha256 === ref.sha256,
      'SLOT_MISMATCH', 'observation.materialResults', 'blob reference differs from its owner');
  }
  for (const result of observation.checkResults) {
    if (result.status === 'NOT_RUN') continue;
    const check = request.checkPlan.find(v => v.checkID === result.checkID);
    demand(check, 'CHECK_PLAN_MISMATCH', 'checkID', 'unrequested execution result');
    const process = await loadMaterial(uow, check.processRef, caseID, ['PROCESS']);
    m.bindExecution(result.execution, check, process.body.data, caseID);
  }
  // These checks bind declarations; they do not verify off-chain bytes.
}
async function checkSources(uow, material, caseID) {
  // All reads precede staging this material. New/self/forward references are
  // therefore unavailable; only earlier committed versions can form its basis.
  const data = material.data;
  if (material.materialType === 'ARTIFACT') {
    await loadMaterial(uow, data.incidentRef, caseID, ['CONTEXT']);
  } else if (material.materialType === 'PROCESS') {
    for (const input of data.inputBindings) {
      const producer = await loadMaterial(uow, input.sourceRef, caseID, ['ARTIFACT', 'PROCESS']);
      if (input.inputType === 'RECORD') {
        demand(producer.body.materialType === 'PROCESS' && producer.body.data.methodSpec.mode === 'MANUAL',
          'INVALID_REFERENCE', 'input.sourceRef', 'RECORD input requires a MANUAL process result');
      } else {
        const outputs = producer.body.materialType === 'ARTIFACT'
          ? [producer.body.data.blobDescriptor] : producer.body.data.outputs;
        const descriptor = outputs.find(v => v.slotID === input.slotID);
        demand(descriptor && descriptor.sha256 === input.sha256, 'SLOT_MISMATCH', 'input',
          'slot and digest must match the committed producer descriptor');
      }
    }
  } else if (material.materialType === 'FINDING') {
    for (const ref of data.supportRefs) await loadMaterial(uow, ref, caseID, ['ARTIFACT', 'PROCESS']);
  } else if (material.materialType === 'REPORT') {
    for (const ref of material.directDeps) await loadMaterial(uow, ref, caseID, ['FINDING']);
  }
}

async function issueTarget(uow, ref, caseID) {
  return Object.hasOwn(ref, 'objectID') ? loadMaterial(uow, ref, caseID)
    : loadRecordOfKind(uow, ref, caseID, 'REVIEW_REQUEST');
}
async function issueSupport(uow, refs, caseID) {
  for (const ref of refs) await loadMaterial(uow, ref, caseID);
}
async function issueHead(uow, issue) {
  const head = await uow.read('issueHead', [issue.caseID, issue.recordID]);
  demand(head !== null, 'STATE_CORRUPT', 'issueHead', 'missing issue projection');
  issues.validateHead(head, issue);
  const last = await loadRecordOfKind(uow, head.lastEventRef, issue.caseID, head.lastEventRef.kind);
  if (head.lastEventSeq > 1) demand(last.body.issueSeq === head.lastEventSeq &&
    m.canonicalJson(last.body.issueRef) === m.canonicalJson(m.recordRef(issue)), 'STATE_CORRUPT', 'issueHead', 'last event mismatch');
  if (head.latestDispositionRef) {
    const disp = await loadRecordOfKind(uow, head.latestDispositionRef, issue.caseID, 'ISSUE_DISPOSITION');
    demand(disp.body.issueSeq <= head.lastEventSeq && disp.body.disposition === head.status &&
      m.canonicalJson(disp.body.issueRef) === m.canonicalJson(m.recordRef(issue)), 'STATE_CORRUPT', 'issueHead', 'disposition mismatch');
  }
  return head;
}
async function responseAllowed(uow, target, config, identity) {
  if (target.kind === 'REVIEW_REQUEST') {
    demand(identity.role === 'AssuranceReviewer' && s.actorEquals(identity.actor, target.actor),
      'UNAUTHORIZED', 'actor', 'request response requires its authenticated creator');
    return;
  }
  const meta = await uow.read('objectMeta', [target.caseID, target.body.objectID]);
  demand(meta !== null, 'STATE_CORRUPT', 'objectMeta', 'missing owner');
  demand(['AcquisitionOperator', 'ForensicInvestigator'].includes(identity.role) &&
    (s.actorEquals(target.actor, identity.actor) || s.actorEquals(meta.ownerActorRef, identity.actor) ||
      (identity.role === 'ForensicInvestigator' && s.actorEquals(config.leadInvestigator, identity.actor))),
    'UNAUTHORIZED', 'actor', 'response requires target creator, owner, or case lead');
}
async function dispositionAllowed(uow, issue, target, config, identity, disposition) {
  demand(issue.body.issueType === 'CHALLENGE', 'INVALID_ISSUE_TYPE', 'issueType', 'only challenges have disposition');
  if (disposition === 'WITHDRAWN') {
    demand(s.actorEquals(issue.actor, identity.actor), 'UNAUTHORIZED', 'actor', 'only issue submitter may withdraw');
    return;
  }
  demand(identity.role === 'IndependentReviewer' && config.reviewers.some(a => s.actorEquals(a, identity.actor)),
    'UNAUTHORIZED', 'actor', 'disposition requires a case-assigned independent reviewer');
  demand(!s.actorEquals(target.actor, identity.actor), 'SELF_REVIEW_FORBIDDEN', 'actor', 'target author cannot judge own product');
  if (target.kind === 'MATERIAL_VERSION') {
    const meta = await uow.read('objectMeta', [target.caseID, target.body.objectID]);
    demand(meta !== null, 'STATE_CORRUPT', 'objectMeta', 'missing owner');
    demand(!s.actorEquals(meta.ownerActorRef, identity.actor), 'SELF_REVIEW_FORBIDDEN', 'actor', 'target owner cannot judge own product');
  }
  const linked = target.kind === 'REVIEW_REQUEST' ? m.recordRef(target) : issue.body.associatedRequestRef;
  if (linked) {
    const request = await loadRecordOfKind(uow, linked, issue.caseID, 'REVIEW_REQUEST');
    demand(s.actorEquals(request.body.reviewerActorRef, identity.actor), 'UNAUTHORIZED', 'actor', 'linked request reviewer required');
  }
}

function profilesAllowed(config, profile) {
  const supported = new Set(m.getSupportedProfiles().map(item => m.canonicalJson(item.ref)));
  demand(config.profileRefs.some(ref => m.canonicalJson(ref) === m.canonicalJson(profile.ref)) &&
    config.profileRefs.every(ref => supported.has(m.canonicalJson(ref))),
  'POLICY_NOT_ALLOWED', 'config.profileRefs', 'case profiles must be bundled and include alpha0');
}
function reviewProfilesAllowed(config, review) {
  const { policy, verifier } = m.getReviewProfiles();
  const supplied = [review.policyRef, review.verifierSpecRef];
  const supported = [policy.ref, verifier.ref];
  demand(supplied.every((ref, index) => m.canonicalJson(ref) === m.canonicalJson(supported[index])),
    'POLICY_NOT_ALLOWED', 'review', 'unsupported review profile reference');
  demand(supplied.every(ref => config.profileRefs.some(allowed => m.canonicalJson(allowed) === m.canonicalJson(ref))),
    'POLICY_NOT_ALLOWED', 'config.profileRefs', 'review profiles are not authorized for this case');
}
function currentReviewRequest(request, config, admission) {
  profilesAllowed(config, admission);
  demand(m.canonicalJson(request.admissionPolicyRef) === m.canonicalJson(admission.ref),
    'UNSUPPORTED_PROFILE', 'request.admissionPolicyRef', 'legacy request requires a new review under current profiles');
  reviewProfilesAllowed(config, request.body);
}
function envelope(input, actor, profileRef, kind, body) {
  return m.commitEnvelope({ schemaVersion: m.SCHEMA_VERSION, caseID: input.caseID,
    recordID: input.recordID, kind, actor, admissionPolicyRef: profileRef, body });
}
async function stageRecord(uow, record, type, attributes) {
  await uow.stage(type, attributes, record, { createOnly: true });
  await uow.stage('record', [record.caseID, record.recordID], record, { createOnly: true });
}
async function finish(uow, ctx, input, identity, hash, operationName, record, initialize = false) {
  const receipt = await s.stageMutation(uow, { caseID: input.caseID, actor: identity.actor,
    operationID: input.operationID, operationName, inputHash: hash,
    resultRef: m.recordRef(record), recordID: record.recordID, txID: ctx.stub.getTxID(), initialize });
  // The return value is a simulation result. The caller must still obtain a
  // COMMITTED_VALID outcome (or a prior committed receipt) from Fabric.
  await uow.flush();
  return m.canonicalJson(receipt);
}

class LWFAContract extends Contract {
  #deployment;
  #profile;

  constructor(options = {}) {
    super('LWFAContract');
    // Constructor injection is for local tests, never a transaction argument.
    // Fabric's normal construction reads the reviewed, packaged configuration.
    this.#deployment = m.validateDeployment(options.deployment ?? require('./profiles.json').deployment);
    this.#profile = m.getAdmissionProfile();
  }

  async InitializeCase(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    roleAllowed(identity, ['AssuranceReviewer']);
    const input = m.validateInitializeInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx);
    const current = await uow.read('case', [input.caseID]);
    if (current) {
      const record = await loadCase(uow, input.caseID);
      s.requireCaseMember(record.body, identity, ['AssuranceReviewer']);
    } else s.requireCaseMember(input.config, identity, ['AssuranceReviewer']);
    const hash = inputHash('InitializeCase', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'InitializeCase');
    if (prior) return m.canonicalJson(prior);

    demand(current === null, 'DUPLICATE_ID', 'caseID', 'case already exists');
    profilesAllowed(input.config, this.#profile);
    // A case assignment may restrict trusted roles, not invent a role/MSP
    // combination outside the operator-reviewed deployment mapping.
    for (const member of input.config.members) {
      for (const role of member.roles) demand(this.#deployment.roleMSPs[role].includes(member.actor.mspID),
        'UNAUTHORIZED', 'config.members', 'member role is not permitted for this MSP');
    }
    const record = envelope(input, identity.actor, this.#profile.ref, 'CASE_CONFIG', input.config);
    await stageRecord(uow, record, 'case', [input.caseID]);
    return finish(uow, ctx, input, identity, hash, 'InitializeCase', record, true);
  }

  async RegisterMaterial(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    roleAllowed(identity, ['AcquisitionOperator', 'ForensicInvestigator']);
    const input = m.validateRegisterInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity, ['AcquisitionOperator', 'ForensicInvestigator']);
    if (identity.role === 'AcquisitionOperator') demand(['CONTEXT', 'ARTIFACT'].includes(input.material.materialType),
      'UNAUTHORIZED', 'materialType', 'acquisition operator can register only incident context and artifacts');
    const hash = inputHash('RegisterMaterial', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'RegisterMaterial');
    if (prior) return m.canonicalJson(prior);

    profilesAllowed(caseRecord.body, this.#profile);
    const { material } = input;
    const meta = await uow.read('objectMeta', [input.caseID, material.objectID]);
    let nextVersion;
    let owner;
    if (meta === null) {
      demand(material.predecessorRef === null, 'INVALID_REFERENCE', 'predecessorRef', 'new object cannot have a predecessor');
      nextVersion = 1; owner = identity.actor;
    } else {
      m.assertExactShape(meta, ['caseID', 'objectID', 'materialType', 'ownerActorRef', 'latestVersion'], 'objectMeta');
      m.assertActorRef(meta.ownerActorRef); s.sequenceKey(meta.latestVersion);
      demand(meta.caseID === input.caseID && meta.objectID === material.objectID,
        'STATE_CORRUPT', 'objectMeta', 'object identity mismatch');
      demand(meta.materialType === material.materialType, 'INVALID_REFERENCE', 'materialType', 'object type cannot change');
      demand(s.actorEquals(meta.ownerActorRef, identity.actor) ||
        (identity.role === 'ForensicInvestigator' && s.actorEquals(caseRecord.body.leadInvestigator, identity.actor)),
      'VERSION_OWNER_REQUIRED', 'actor', 'revision requires the owner or assigned lead investigator');
      demand(material.predecessorRef !== null && material.predecessorRef.version <= meta.latestVersion,
        'INVALID_REFERENCE', 'predecessorRef', 'revision requires an explicit existing predecessor');
      await loadMaterial(uow, material.predecessorRef, input.caseID, [material.materialType]);
      demand(meta.latestVersion < m.LIMITS.version, 'LIMIT_EXCEEDED', 'version', 'version counter exhausted');
      nextVersion = meta.latestVersion + 1; owner = meta.ownerActorRef;
    }
    await checkSources(uow, material, input.caseID);
    const body = m.validateMaterialBody({ ...material, version: nextVersion }, input.caseID);
    const record = envelope(input, identity.actor, this.#profile.ref, 'MATERIAL_VERSION', body);
    await stageRecord(uow, record, 'material', [input.caseID, material.objectID, s.sequenceKey(nextVersion)]);
    await uow.stage('objectMeta', [input.caseID, material.objectID], { caseID: input.caseID,
      objectID: material.objectID, materialType: material.materialType, ownerActorRef: owner, latestVersion: nextVersion });
    return finish(uow, ctx, input, identity, hash, 'RegisterMaterial', record);
  }

  async OpenReview(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    roleAllowed(identity, ['AssuranceReviewer']);
    const input = m.validateReviewInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity, ['AssuranceReviewer']);
    const hash = inputHash('OpenReview', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'OpenReview');
    if (prior) return m.canonicalJson(prior);
    profilesAllowed(caseRecord.body, this.#profile);
    reviewProfilesAllowed(caseRecord.body, input.review);
    await checkReviewSources(uow, input.review, input.caseID);
    const target = await loadMaterial(uow, input.review.targetRef, input.caseID, ['FINDING', 'REPORT']);
    demand(!s.actorEquals(target.actor, input.review.reviewerActorRef),
      'UNAUTHORIZED', 'reviewerActorRef', 'reviewer cannot be the target record author');
    const reviewerMember = caseRecord.body.members.find(member => s.actorEquals(member.actor, input.review.reviewerActorRef));
    demand(reviewerMember && reviewerMember.roles.includes('IndependentReviewer') &&
      caseRecord.body.reviewers.some(actor => s.actorEquals(actor, input.review.reviewerActorRef)),
      'UNAUTHORIZED', 'reviewerActorRef', 'reviewer is not assigned to this case');
    if (input.review.predecessorRequestRef) {
      await loadRecordOfKind(uow, input.review.predecessorRequestRef, input.caseID, 'REVIEW_REQUEST');
    }
    const record = envelope(input, identity.actor, this.#profile.ref, 'REVIEW_REQUEST', input.review);
    await uow.stage('record', [input.caseID, input.recordID], record, { createOnly: true });
    return finish(uow, ctx, input, identity, hash, 'OpenReview', record);
  }

  async RegisterPackage(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    roleAllowed(identity, ['ForensicInvestigator', 'IndependentReviewer']);
    const input = m.validatePackageInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity);
    const hash = inputHash('RegisterPackage', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'RegisterPackage');
    if (prior) return m.canonicalJson(prior);

    const request = await loadRecordOfKind(uow, input.package.requestRef, input.caseID, 'REVIEW_REQUEST');
    currentReviewRequest(request, caseRecord.body, this.#profile);
    demand(identity.role === 'ForensicInvestigator' || s.actorEquals(identity.actor, request.body.reviewerActorRef),
      'UNAUTHORIZED', 'actor', 'package registrar must be investigator or designated reviewer');
    const record = envelope(input, identity.actor, this.#profile.ref, 'PACKAGE_RECORD', input.package);
    await uow.stage('record', [input.caseID, input.recordID], record, { createOnly: true });
    return finish(uow, ctx, input, identity, hash, 'RegisterPackage', record);
  }

  async AppendObservation(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    roleAllowed(identity, ['IndependentReviewer']);
    const input = m.validateObservationInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity, ['IndependentReviewer']);
    const hash = inputHash('AppendObservation', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'AppendObservation');
    if (prior) return m.canonicalJson(prior);

    const request = await loadRecordOfKind(uow, input.observation.intendedRequestRef, input.caseID, 'REVIEW_REQUEST');
    currentReviewRequest(request, caseRecord.body, this.#profile);
    demand(s.actorEquals(identity.actor, request.body.reviewerActorRef),
      'UNAUTHORIZED', 'actor', 'only the designated reviewer may append an observation');
    // The rejected input may itself carry an invalid/future/foreign chi.
    // Block inclusion is verified off-chain; the actual channel is enforced here.
    demand(input.observation.checkpointHistory.channelID === ctx.stub.getChannelID(),
      'CHECKPOINT_MISMATCH', 'checkpointHistory.channelID', 'history must use the transaction channel');
    m.validateObservationBinding(input.observation, request.body, input.caseID);
    if (input.observation.mode === 'CHECKS') {
      const pkg = await loadRecordOfKind(uow, input.observation.packageRef, input.caseID, 'PACKAGE_RECORD');
      demand(m.canonicalJson(pkg.admissionPolicyRef) === m.canonicalJson(this.#profile.ref),
        'UNSUPPORTED_PROFILE', 'package.admissionPolicyRef', 'legacy package is not admitted for a new observation');
      demand(m.canonicalJson(pkg.body.requestRef) === m.canonicalJson(input.observation.intendedRequestRef) &&
        pkg.body.manifestHash === input.observation.manifestHash,
      'INVALID_REFERENCE', 'packageRef', 'package is not bound to the intended request and manifest');
      await checkObservationSources(uow, input.observation, request.body, input.caseID);
    }
    const attemptKey = [input.caseID, request.recordID, identity.actor.mspID,
      identity.actor.clientID, input.observation.attemptID];
    demand(await uow.read('observationAttempt', attemptKey) === null,
      'DUPLICATE_ATTEMPT', 'observation.attemptID', 'attempt already registered for this reviewer and request');
    const record = envelope(input, identity.actor, this.#profile.ref, 'OBSERVATION', input.observation);
    await uow.stage('record', [input.caseID, input.recordID], record, { createOnly: true });
    await uow.stage('observationAttempt', attemptKey, { observationRef: m.recordRef(record) }, { createOnly: true });
    return finish(uow, ctx, input, identity, hash, 'AppendObservation', record);
  }


  async RecordIssue(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    const input = issues.validateIssueInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx), caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity);
    const hash = inputHash('RecordIssue', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'RecordIssue');
    if (prior) return m.canonicalJson(prior);
    profilesAllowed(caseRecord.body, this.#profile);
    await issueTarget(uow, input.issue.targetRef, input.caseID);
    await issueSupport(uow, input.issue.supportRefs, input.caseID);
    if (input.issue.associatedRequestRef) await loadRecordOfKind(uow, input.issue.associatedRequestRef, input.caseID, 'REVIEW_REQUEST');
    const record = envelope(input, identity.actor, this.#profile.ref, 'ISSUE', input.issue);
    await uow.stage('record', [input.caseID, input.recordID], record, {createOnly: true});
    await uow.stage('issueHead', [input.caseID, input.recordID], issues.initialHead(record), {createOnly: true});
    return finish(uow, ctx, input, identity, hash, 'RecordIssue', record);
  }

  async RespondIssue(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    roleAllowed(identity, ['AcquisitionOperator', 'ForensicInvestigator', 'AssuranceReviewer']);
    const input = issues.validateResponseInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx), caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity);
    const hash = inputHash('RespondIssue', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'RespondIssue');
    if (prior) return m.canonicalJson(prior);
    profilesAllowed(caseRecord.body, this.#profile);
    const issue = await loadRecordOfKind(uow, input.response.issueRef, input.caseID, 'ISSUE');
    const target = await issueTarget(uow, issue.body.targetRef, input.caseID);
    await responseAllowed(uow, target, caseRecord.body, identity);
    await issueSupport(uow, input.response.supportRefs, input.caseID);
    const head = await issueHead(uow, issue);
    demand(head.lastEventSeq < m.LIMITS.version, 'LIMIT_EXCEEDED', 'issueSeq', 'issue sequence exhausted');
    const body = issues.validateResponseBody({...input.response, issueSeq: head.lastEventSeq + 1,
      previousEventRef: head.lastEventRef}, input.caseID, true);
    const record = envelope(input, identity.actor, this.#profile.ref, 'ISSUE_RESPONSE', body);
    await uow.stage('record', [input.caseID, input.recordID], record, {createOnly: true});
    await uow.stage('issueHead', [input.caseID, issue.recordID], issues.applyEvent(head, issue, record));
    return finish(uow, ctx, input, identity, hash, 'RespondIssue', record);
  }

  async DisposeIssue(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    const input = issues.validateDispositionInput(rawInput(inputJson));
    const uow = new s.UnitOfWork(ctx), caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity);
    const hash = inputHash('DisposeIssue', input, identity.actor);
    const prior = await s.readReceipt(uow, input.caseID, identity.actor, input.operationID, hash, 'DisposeIssue');
    if (prior) return m.canonicalJson(prior);
    profilesAllowed(caseRecord.body, this.#profile);
    const issue = await loadRecordOfKind(uow, input.disposition.issueRef, input.caseID, 'ISSUE');
    const target = await issueTarget(uow, issue.body.targetRef, input.caseID);
    await dispositionAllowed(uow, issue, target, caseRecord.body, identity, input.disposition.disposition);
    await issueSupport(uow, input.disposition.supportRefs, input.caseID);
    const head = await issueHead(uow, issue);
    demand(input.disposition.expectedIssueSeq === head.lastEventSeq, 'STALE_ISSUE_BASIS', 'expectedIssueSeq', 'read latest issue history before disposition');
    demand(head.lastEventSeq < m.LIMITS.version, 'LIMIT_EXCEEDED', 'issueSeq', 'issue sequence exhausted');
    const body = issues.validateDispositionBody({...input.disposition, issueSeq: head.lastEventSeq + 1,
      previousEventRef: head.lastEventRef}, input.caseID, true);
    const record = envelope(input, identity.actor, this.#profile.ref, 'ISSUE_DISPOSITION', body);
    await uow.stage('record', [input.caseID, input.recordID], record, {createOnly: true});
    await uow.stage('issueHead', [input.caseID, issue.recordID], issues.applyEvent(head, issue, record));
    return finish(uow, ctx, input, identity, hash, 'DisposeIssue', record);
  }

  async GetIssueHead(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment), input = rawInput(inputJson);
    m.assertExactShape(input, ['caseID', 'issueRef'], 'query'); m.assertID(input.caseID, 'caseID');
    const uow = new s.UnitOfWork(ctx), caseRecord = await loadCase(uow, input.caseID);
    s.requireCaseMember(caseRecord.body, identity);
    const issue = await loadRecordOfKind(uow, input.issueRef, input.caseID, 'ISSUE');
    return m.canonicalJson(await issueHead(uow, issue));
  }

  async GetCase(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    const input = rawInput(inputJson); m.assertExactShape(input, ['caseID'], 'query'); m.assertID(input.caseID, 'caseID');
    const record = await loadCase(new s.UnitOfWork(ctx), input.caseID);
    s.requireCaseMember(record.body, identity);
    return m.canonicalJson(record);
  }

  async GetMaterialVersion(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    const input = rawInput(inputJson);
    m.assertExactShape(input, ['caseID', 'objectID', 'version'], 'query');
    m.assertID(input.caseID, 'caseID'); m.assertID(input.objectID, 'objectID'); s.sequenceKey(input.version);
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID); s.requireCaseMember(caseRecord.body, identity);
    const record = trustedEnvelope(await uow.read('material',
      [input.caseID, input.objectID, s.sequenceKey(input.version)]), input.caseID, 'MATERIAL_VERSION');
    const ref = m.materialRef(record);
    demand(ref.objectID === input.objectID && ref.version === input.version,
      'STATE_CORRUPT', 'material', 'stored material does not match selector');
    return m.canonicalJson(record);
  }

  async GetRecord(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    const input = rawInput(inputJson); m.assertExactShape(input, ['caseID', 'selector'], 'query');
    m.assertID(input.caseID, 'caseID');
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID); s.requireCaseMember(caseRecord.body, identity);
    const selector = input.selector;
    if (selector?.type === 'RECORD') {
      m.assertExactShape(selector, ['type', 'recordID'], 'selector'); m.assertID(selector.recordID, 'recordID');
      const record = trustedEnvelope(await uow.read('record', [input.caseID, selector.recordID]), input.caseID);
      demand(record.recordID === selector.recordID, 'STATE_CORRUPT', 'recordID', 'record selector mismatch');
      return m.canonicalJson(record);
    }
    m.assertExactShape(selector, ['type', 'actor', 'operationID'], 'selector');
    demand(selector.type === 'RECEIPT', 'SCHEMA_ERROR', 'selector.type', 'RECORD or RECEIPT required');
    m.assertActorRef(selector.actor); m.assertID(selector.operationID, 'operationID');
    const receipt = await uow.read('operation', [input.caseID, selector.actor.mspID, selector.actor.clientID, selector.operationID]);
    demand(receipt !== null, 'NOT_FOUND', 'receipt', 'operation receipt does not exist');
    s.validateReceipt(receipt);
    demand(receipt.caseID === input.caseID && receipt.operationID === selector.operationID &&
      s.actorEquals(receipt.actor, selector.actor), 'STATE_CORRUPT', 'receipt', 'receipt selector mismatch');
    return m.canonicalJson(receipt);
  }

  async ListCaseJournal(ctx, inputJson) {
    const identity = s.authenticate(ctx, this.#deployment);
    const input = rawInput(inputJson);
    m.assertExactShape(input, ['caseID', 'afterSequence', 'limit'], 'query'); m.assertID(input.caseID, 'caseID');
    demand(Number.isInteger(input.afterSequence) && input.afterSequence >= 0 && input.afterSequence <= m.LIMITS.version,
      'SCHEMA_ERROR', 'afterSequence', 'invalid sequence');
    demand(Number.isInteger(input.limit) && input.limit >= 1 && input.limit <= 50,
      'SCHEMA_ERROR', 'limit', 'limit must be between 1 and 50');
    const uow = new s.UnitOfWork(ctx);
    const caseRecord = await loadCase(uow, input.caseID); s.requireCaseMember(caseRecord.body, identity);
    const head = await uow.read('caseHead', [input.caseID]);
    demand(head !== null && head.caseID === input.caseID, 'STATE_CORRUPT', 'caseHead', 'missing or invalid head');
    s.sequenceKey(head.sequence);
    demand(input.afterSequence <= head.sequence, 'SCHEMA_ERROR', 'afterSequence', 'cursor is beyond case head');
    const last = Math.min(head.sequence, input.afterSequence + input.limit);
    const items = [];
    for (let seq = input.afterSequence + 1; seq <= last; seq++) {
      const entry = await uow.read('journal', [input.caseID, s.sequenceKey(seq)]);
      demand(entry !== null && entry.caseID === input.caseID && entry.sequence === seq,
        'STATE_CORRUPT', 'journal', 'missing or inconsistent journal entry');
      items.push(entry);
    }
    // This is a bounded current-state query, not a historical chi/kappa proof.
    return m.canonicalJson({ caseID: input.caseID, headSequence: head.sequence,
      items, nextAfterSequence: last, hasMore: last < head.sequence });
  }
}

// Public operations accept one JSON string; query metadata uses EVALUATE.
for (const [name, submit] of [
  ['InitializeCase', true], ['RegisterMaterial', true], ['GetCase', false],
  ['GetMaterialVersion', false], ['GetRecord', false], ['ListCaseJournal', false],
  ['OpenReview', true], ['RegisterPackage', true], ['AppendObservation', true],
  ['RecordIssue', true], ['RespondIssue', true], ['DisposeIssue', true], ['GetIssueHead', false],
]) {
  Transaction(submit)(LWFAContract.prototype, name);
  Param('inputJson', 'string', 'Strict LWFA JSON request')(LWFAContract.prototype, name);
  Returns('string')(LWFAContract.prototype, name);
}

module.exports = LWFAContract;
