'use strict';
// LWFA_DISCLOSURE_2 — mandatory external disclosure for one review request.
//
// It does NOT change the nu0-m2 v5 results (binding, context, history). A package can
// remain context-SATISFIED while this layer reports that registered issues exist outside
// the frozen basis, or that a record's claimed actor is not the committed transaction
// creator. Everything here is derived from the same trusted-peer snapshot used by
// lwfa-v0.5.1/client/{package,issues}.js; nothing is backfilled into the package.
const core = require('./core');
const m = core.req('chaincode/model');
const I = core.req('client/issues');
const P = core.req('client/package');
const { same } = core.req('client/io');
const policy = require('./policy');

const FORMAT = 'LWFA_DISCLOSURE_2';
const UNRESOLVED = new Set(['OPEN', 'ANSWERED']);
const byID = (a, b) => (a.recordID < b.recordID ? -1 : a.recordID > b.recordID ? 1 : 0);

function position(snapshot, id) {
  const p = snapshot.births.get(id);
  if (!p) throw new Error(`MISSING_RECORD_BIRTH:${id}`);
  return p;
}
function before(a, b) {
  return BigInt(a.block) < BigInt(b.block) || (a.block === b.block && a.index < b.index);
}
const mkey = (objectID, version) => `${objectID}/${version}`;

// ---------------------------------------------------------------- basis lag
function basisLag(snapshot, request, atKappa) {
  const chi = BigInt(request.body.checkpointBasis.blockNumber), born = position(snapshot, request.recordID);
  const between = [...atKappa.values()].filter(e => e.recordID !== request.recordID &&
    BigInt(position(snapshot, e.recordID).block) > chi && before(position(snapshot, e.recordID), born));
  const kinds = {};
  for (const e of between) kinds[e.kind] = (kinds[e.kind] || 0) + 1;
  return { chiBlock: String(chi), requestBlock: born.block, blocksAfterChi: String(BigInt(born.block) - chi),
    caseRecordsBetweenChiAndRequest: between.length, recordKindsBetween: kinds };
}

// ------------------------------------------- issues on basis materials after chi
function postBasisIssues(snapshot, request, materials, atKappa) {
  const chi = BigInt(request.body.checkpointBasis.blockNumber), born = position(snapshot, request.recordID);
  const reqRef = m.recordRef(request), refs = materials.map(e => m.materialRef(e)), out = [];
  for (const e of [...atKappa.values()].sort(byID)) {
    if (e.kind !== 'ISSUE' || !refs.some(r => same(r, e.body.targetRef))) continue;
    const p = position(snapshot, e.recordID);
    if (BigInt(p.block) <= chi) continue; // at chi: already a mandatory package obligation
    const head = I.project(snapshot, atKappa, e);
    out.push({ issueRef: refOf(e), issueType: e.body.issueType, targetRef: e.body.targetRef,
      birth: { block: p.block, index: p.index },
      timing: before(p, born) ? 'AFTER_CHI_BEFORE_REQUEST' : 'AFTER_REQUEST_THROUGH_KAPPA',
      linkedToRequest: e.body.associatedRequestRef !== null && same(e.body.associatedRequestRef, reqRef),
      statusAtKappa: head.status, lastEventSeq: head.lastEventSeq, events: I.eventsFor(atKappa, e).map(refOf) });
  }
  return out;
}
const refOf = e => m.recordRef(e);

// All older versions of the same object, including siblings skipped by predecessorRef.
// Issues on a version already in the current basis retain their BASIS obligation.
function predecessorIssues(snapshot, request, materials, atKappa) {
  const born = position(snapshot, request.recordID), all = [...atKappa.values()];
  const versions = new Map(all.filter(e => e.kind === 'MATERIAL_VERSION')
    .map(e => [`${e.caseID}/${mkey(e.body.objectID, e.body.version)}`, e]));
  const inBasis = new Set(materials.map(e => `${e.caseID}/${mkey(e.body.objectID,e.body.version)}`));
  const byVersion = new Map(), missing = [];
  for (const material of [...materials].sort(byID)) {
    const explicit = new Set(); let ref = material.body.predecessorRef;
    while (ref) {
      const key = `${ref.caseID}/${mkey(ref.objectID,ref.version)}`;
      if (explicit.has(key)) throw new Error('CYCLIC_VERSION_HISTORY');
      explicit.add(key);
      const v = versions.get(key);
      if (!v || !same(m.materialRef(v),ref)) { missing.push({basisMaterialRef:m.materialRef(material),predecessorRef:ref}); break; }
      ref = v.body.predecessorRef;
    }
    for (const v of all.filter(e => e.kind === 'MATERIAL_VERSION' && e.caseID === material.caseID &&
      e.body.objectID === material.body.objectID && e.body.version < material.body.version).sort(byID)) {
      const key = `${v.caseID}/${mkey(v.body.objectID,v.body.version)}`;
      const item = byVersion.get(key) || {record:v,basisMaterialRefs:[],explicitPredecessorOf:[],inCurrentBasis:inBasis.has(key)};
      item.basisMaterialRefs.push(m.materialRef(material));
      if (explicit.has(key)) item.explicitPredecessorOf.push(m.materialRef(material));
      byVersion.set(key,item);
    }
  }
  if (byVersion.size > policy.DEFINITION.limits.maxEarlierVersions) throw new Error('DISCLOSURE_EARLIER_VERSION_LIMIT');
  const out = [], earlierVersions = [];
  for (const v of [...byVersion.values()].sort((a,b)=>byID(a.record,b.record))) {
    const ref = m.materialRef(v.record);
    const issues = all.filter(e=>e.kind==='ISSUE' && same(e.body.targetRef,ref)).sort(byID);
    earlierVersions.push({earlierVersionRef:ref,basisMaterialRefs:v.basisMaterialRefs,
      explicitPredecessorOf:v.explicitPredecessorOf,inCurrentBasis:v.inCurrentBasis,
      meaning:v.inCurrentBasis?'CURRENT_BASIS_REQUIRED':'EARLIER_VERSION_DISCLOSURE_ADVISORY',
      issueRefs:issues.map(refOf)});
    for (const issue of issues) {
      const head = I.project(snapshot,atKappa,issue);
      out.push({basisMaterialRef:v.basisMaterialRefs[0],basisMaterialRefs:v.basisMaterialRefs,
        predecessorRef:ref,earlierVersionRef:ref,explicitPredecessor:v.explicitPredecessorOf.length>0,
        inCurrentBasis:v.inCurrentBasis,issueRef:m.recordRef(issue),issueType:issue.body.issueType,
        statusAtKappa:head.status,unresolvedChallenge:issue.body.issueType==='CHALLENGE'&&UNRESOLVED.has(head.status),
        bornBeforeRequest:before(position(snapshot,issue.recordID),born),events:I.eventsFor(atKappa,issue).map(refOf)});
    }
  }
  return {items:out,earlierVersions,missingPredecessors:missing};
}
function previousReviews(snapshot,request,atKappa) {
  const all=[...atKappa.values()], born=position(snapshot,request.recordID);
  const requests=all.filter(e=>e.kind==='REVIEW_REQUEST' && e.caseID===request.caseID &&
    same(e.body.targetRef,request.body.targetRef) && before(position(snapshot,e.recordID),born)).sort(byID);
  if(requests.length>policy.DEFINITION.limits.maxPriorReviews)throw new Error('DISCLOSURE_PRIOR_REVIEW_LIMIT');
  return requests.map(r=>{
    const ref=m.recordRef(r);
    const issues=all.filter(e=>e.kind==='ISSUE' && (same(e.body.targetRef,ref)||
      (e.body.associatedRequestRef!==null&&same(e.body.associatedRequestRef,ref)))).sort(byID);
    const packages=all.filter(e=>e.kind==='PACKAGE_RECORD'&&same(e.body.requestRef,ref)).sort(byID);
    const observations=all.filter(e=>e.kind==='OBSERVATION'&&same(e.body.intendedRequestRef,ref)).sort(byID);
    return {requestRef:ref,targetRef:r.body.targetRef,checkpointBasis:r.body.checkpointBasis,scope:r.body.scope,
      policyRef:r.body.policyRef,verifierSpecRef:r.body.verifierSpecRef,checkPlan:r.body.checkPlan,
      predecessorRequestRef:r.body.predecessorRequestRef,
      historyInterpretation:'NOT_REEVALUATED_HISTORY',packageRefs:packages.map(refOf),observationRefs:observations.map(refOf),
      issues:issues.map(e=>({issueRef:m.recordRef(e),statusAtKappa:I.project(snapshot,atKappa,e).status,
        issueType:e.body.issueType,events:I.eventsFor(atKappa,e).map(refOf)}))};
  });
}

// ------------------------------------------------ actor <-> committed creator
function creatorBinding(snapshot, identities, scope) {
  if (!identities) return { status: 'NOT_EVALUATED', reason: 'No block-derived creator identities supplied', records: [] };
  const records = scope.map(e => {
    const p = position(snapshot, e.recordID), id = identities.get(p.txID);
    let status;
    if (!p.txID || !id) status = 'CREATOR_MISSING';
    else if (id.status !== 'DERIVED') status = id.status;
    else if (id.block !== undefined && (String(id.block) !== String(p.block) || id.index !== p.index)) status = 'CREATOR_POSITION_MISMATCH';
    else if (!same(id.actor, e.actor)) status = 'ACTOR_CREATOR_MISMATCH';
    else status = 'BOUND';
    return { recordID: e.recordID, kind: e.kind, txID: p.txID ?? null, status,
      claimedActor: e.actor, creatorActor: id?.actor ?? null, creatorRole: id?.role ?? null };
  });
  const bad = records.filter(r => r.status !== 'BOUND');
  const status = bad.length === 0 ? 'BOUND'
    : bad.some(r => ['ACTOR_CREATOR_MISMATCH', 'CREATOR_POSITION_MISMATCH'].includes(r.status)) ? 'MISMATCH' : 'INCOMPLETE';
  return { status, records };
}

const {authorityReplay} = require('./authority');

// The caller supplies the reviewer-pinned snapshot endpoint. A requested smaller
// checkpoint must use a separately obtained historical snapshot, never silently
// slice newer evidence inside this API.
function assertEndpoint(snapshot,request,historyCheckpoint) {
  m.assertCheckpoint(historyCheckpoint);
  const last=snapshot.headers.at(-1);
  if(!last||last.number!==historyCheckpoint.blockNumber||last.hash!==historyCheckpoint.blockHeaderHash)
    throw new Error('DISCLOSURE_CHECKPOINT_NOT_SNAPSHOT_ENDPOINT');
  if(historyCheckpoint.channelID!==request.body.checkpointBasis.channelID)throw new Error('DISCLOSURE_CHANNEL_MISMATCH');
  if(snapshot.records.size>policy.DEFINITION.limits.maxCaseRecords)throw new Error('DISCLOSURE_CASE_RECORD_LIMIT');
  for(const e of snapshot.records.values()) {
    if(e.caseID!==request.caseID)throw new Error('DISCLOSURE_MIXED_CASE_SNAPSHOT');
    if(BigInt(position(snapshot,e.recordID).block)>BigInt(last.number))throw new Error('DISCLOSURE_RECORD_AFTER_ENDPOINT');
  }
}
function assess({snapshot,request,historyCheckpoint,identities=null}) {
  assertEndpoint(snapshot,request,historyCheckpoint);
  const atKappa=I.at(snapshot,historyCheckpoint);
  const materials=P.closure(I.at(snapshot,request.body.checkpointBasis),request.body);
  const summary=I.historySummary(snapshot,request,historyCheckpoint,materials);
  const lag=basisLag(snapshot,request,atKappa),post=postBasisIssues(snapshot,request,materials,atKappa);
  const lineage=predecessorIssues(snapshot,request,materials,atKappa),priorReviews=previousReviews(snapshot,request,atKappa);
  if(lineage.missingPredecessors.length)throw new Error('DISCLOSURE_MISSING_PREDECESSOR');
  const scopeIDs=new Set([...atKappa.values()].filter(e=>e.kind==='CASE_CONFIG').map(e=>e.recordID));
  for(const e of materials)scopeIDs.add(e.recordID);
  for(const x of summary.entries)scopeIDs.add(x.record.recordID);
  const addRef=ref=>{
    const record=Object.hasOwn(ref,'objectID')?[...atKappa.values()].find(e=>e.kind==='MATERIAL_VERSION'&&same(m.materialRef(e),ref)):
      atKappa.get(ref.recordID);
    if(!record||(!Object.hasOwn(ref,'objectID')&&!same(m.recordRef(record),ref)))throw new Error('DISCLOSURE_REQUIRED_REFERENCE_MISSING');
    scopeIDs.add(record.recordID);
  };
  for(const x of [...post,...lineage.items]){addRef(x.issueRef);x.events.forEach(addRef);}
  for(const v of lineage.earlierVersions)addRef(v.earlierVersionRef);
  for(const r of priorReviews) {
    addRef(r.requestRef);r.packageRefs.forEach(addRef);r.observationRefs.forEach(addRef);
    for(const i of r.issues){addRef(i.issueRef);i.events.forEach(addRef);}
  }
  // Related issue targets are explicit evidence for authority checks. No recursive
  // expansion into unrelated investigations or semantic-equivalence search.
  for(const id of scopeIDs) {
    const e=atKappa.get(id);
    if(e.kind==='ISSUE') {
      addRef(e.body.targetRef);
      if(e.body.associatedRequestRef!==null)addRef(e.body.associatedRequestRef);
    }
    if(e.kind==='REVIEW_REQUEST')addRef(e.body.targetRef);
    if(e.kind==='MATERIAL_VERSION'&&e.body.version>1) {
      const ownerVersion=[...atKappa.values()].find(v=>v.kind==='MATERIAL_VERSION'&&
        v.caseID===e.caseID&&v.body.objectID===e.body.objectID&&v.body.version===1);
      if(!ownerVersion)throw new Error('DISCLOSURE_OWNER_VERSION_MISSING');
      addRef(m.materialRef(ownerVersion));
    }
    if(scopeIDs.size>policy.DEFINITION.limits.maxRequiredRecords)throw new Error('DISCLOSURE_REQUIRED_RECORD_LIMIT');
  }
  if(scopeIDs.size>policy.DEFINITION.limits.maxRequiredRecords)throw new Error('DISCLOSURE_REQUIRED_RECORD_LIMIT');
  const scope=[...scopeIDs].map(id=>atKappa.get(id)).sort(byID);
  scope.forEach(e=>m.verifyEnvelopeCommitment(e));
  const binding=creatorBinding(snapshot,identities,scope),authority=authorityReplay(snapshot,identities,scope,atKappa);
  const flags=[];
  if(post.some(x=>x.timing==='AFTER_CHI_BEFORE_REQUEST'))flags.push('POST_BASIS_ISSUE_BEFORE_REQUEST');
  if(post.some(x=>x.timing==='AFTER_CHI_BEFORE_REQUEST'&&x.issueType==='CHALLENGE'&&UNRESOLVED.has(x.statusAtKappa)))flags.push('UNRESOLVED_CHALLENGE_EXCLUDED_BY_CHI');
  if(post.some(x=>x.timing==='AFTER_REQUEST_THROUGH_KAPPA'&&!x.linkedToRequest))flags.push('POST_REQUEST_BASIS_ISSUE_UNLINKED');
  if(lineage.items.some(x=>x.unresolvedChallenge&&x.explicitPredecessor&&!x.inCurrentBasis))flags.push('UNRESOLVED_PREDECESSOR_CHALLENGE');
  if(lineage.items.some(x=>x.unresolvedChallenge&&!x.explicitPredecessor&&!x.inCurrentBasis))flags.push('UNRESOLVED_EARLIER_VERSION_CHALLENGE');
  if(priorReviews.some(r=>r.issues.some(i=>i.issueType==='CHALLENGE'&&UNRESOLVED.has(i.statusAtKappa))))flags.push('UNRESOLVED_PRIOR_REVIEW_CHALLENGE');
  if(binding.status==='MISMATCH')flags.push('ACTOR_CREATOR_MISMATCH');
  if(binding.status==='INCOMPLETE')flags.push('CREATOR_BINDING_INCOMPLETE');
  if(binding.status==='NOT_EVALUATED')flags.push('CREATOR_BINDING_NOT_EVALUATED');
  if(authority.status==='VIOLATIONS')flags.push('AUTHORITY_VIOLATION');
  if(authority.status==='INCOMPLETE')flags.push('AUTHORITY_INCOMPLETE');
  if(authority.status==='NOT_EVALUATED')flags.push('AUTHORITY_NOT_EVALUATED');
  return m.parseJson(m.canonicalJson({formatVersion:FORMAT,policyRef:policy.getPolicy().ref,
    caseID:request.caseID,intendedRequestRef:m.recordRef(request),checkpointBasis:request.body.checkpointBasis,
    checkpointHistory:historyCheckpoint,legacyPolicyRef:request.body.policyRef,legacyVerifierSpecRef:request.body.verifierSpecRef,
    coverage:{status:'SATISFIED',source:'RECOMPUTED_FROM_REVIEWER_SNAPSHOT',requiredRecordCount:scope.length,
      meaning:'All records required by this external protocol are disclosed; open concerns do not make coverage incomplete'},
    basisLag:lag,postBasisIssues:post,predecessorIssues:lineage.items,earlierVersions:lineage.earlierVersions,
    missingPredecessors:[],priorReviews,
    requiredRecords:scope.map(record=>({record,position:position(snapshot,record.recordID)})),
    creatorBinding:binding,authority,flags:flags.sort(),
    meaning:'Mandatory external disclosure v2 over registered scoped records through reviewer-pinned kappa; legacy v5 results unchanged; no substantive truth claim'}));
}
function verifyPresentedDisclosure(presented,input) {
  // input MUST come from the independent reviewer, not from the presented output.
  const expected=assess(input),reasons=[];
  if(!presented||typeof presented!=='object'||Array.isArray(presented))return {
    coverageStatus:'UNSATISFIED',policyRef:policy.getPolicy().ref,reasonPaths:['DISCLOSURE_MISSING_OR_INVALID'],
    missingRecordIDs:expected.requiredRecords.map(x=>x.record.recordID),unexpectedRecordIDs:[],changedRecordIDs:[]};
  const expectedIDs=new Map(expected.requiredRecords.map(x=>[x.record.recordID,x]));
  const got=Array.isArray(presented.requiredRecords)?presented.requiredRecords:[];
  const suppliedIDs=got.map(x=>x?.record?.recordID),missing=[],unexpected=[],changed=[];
  for(const [id,value] of expectedIDs){
    const item=got.find(x=>x?.record?.recordID===id);
    if(!item)missing.push(id);else if(!same(item,value))changed.push(id);
  }
  suppliedIDs.forEach((id,i)=>{if(!expectedIDs.has(id)||suppliedIDs.indexOf(id)!==i)unexpected.push(id??null);});
  for(const key of Object.keys(expected)) {
    try{if(!same(presented[key],expected[key]))reasons.push(key);}catch{reasons.push(key);}
  }
  for(const key of Object.keys(presented))if(!Object.hasOwn(expected,key))reasons.push(`unexpected:${key}`);
  return {coverageStatus:reasons.length?'UNSATISFIED':'SATISFIED',policyRef:policy.getPolicy().ref,
    reasonPaths:reasons.sort(),missingRecordIDs:missing,unexpectedRecordIDs:unexpected,changedRecordIDs:changed,
    meaning:'Presented disclosure compared with independently recomputed complete output; not substantive truth'};
}
module.exports={FORMAT,assess,verifyPresentedDisclosure,basisLag,postBasisIssues,predecessorIssues,previousReviews,creatorBinding,authorityReplay};
