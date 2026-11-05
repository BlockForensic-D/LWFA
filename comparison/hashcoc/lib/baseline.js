'use strict';
// Reduced-obligation reference checker. PCC context, issue selection,
// disclosure completeness, and authority replay are outside its scope.
const {io, P, CP} = require('./core');
const {m, same, sha, safeFile, fileBytes, packageInventory, inputCheck} = io;
class BaselineInputError extends Error {
  constructor(code, domain='input') { super(code); this.code=code; this.domain=domain; }
}
function check(ok, code, domain) { if (!ok) throw new BaselineInputError(code,domain); }
function before(a,b) {return BigInt(a.block)<BigInt(b.block)||(a.block===b.block&&a.index<b.index);}
function digestFile(dir, f, digest, length) {
  try {
    const bytes=inputCheck(()=>fileBytes(safeFile(dir,f.relativePath)));
    return {relativePath:f.relativePath,status:sha(bytes)===digest&&(length===undefined||length===bytes.length)?'HASH_MATCH':'HASH_MISMATCH',
      expectedSHA256:digest,observedSHA256:sha(bytes),expectedByteLength:length,observedByteLength:bytes.length};
  } catch(e) {if(e.code==='ENOENT')return {relativePath:f.relativePath,status:'NOT_OBTAINED',expectedSHA256:digest,expectedByteLength:length};throw e;}
}
function assessHashCoC(options) {
  const {snapshot,identities,request,packageRecord,packageDir,expectedCheckpoint,actualChannel,presentedDisclosure}=options;
  // Anchor failures are operational failures shared with PCC, not baseline verdicts.
  const anchor=CP.validateCheckpoint(snapshot,expectedCheckpoint,actualChannel);
  const out={format:'HASH_COC_REFERENCE_1',checkpoint:anchor.checkpoint,
    input:'NOT_ASSESSABLE',binding:'NOT_ASSESSABLE',creatorBinding:'NOT_ASSESSABLE',
    materialResults:[],toolResults:[],registrationTrail:[],presentedRecordsIntegrity:'NOT_PRESENTED',
    obligations:{materialDependencyCompleteness:'NOT_EVALUATED',basisContextCompleteness:'NOT_EVALUATED',
      presentedHistoryCompleteness:'NOT_EVALUATED',challengeSemantics:'NOT_EVALUATED',scopedAuthority:'NOT_EVALUATED',
      custodyTransferContinuity:'NOT_EVALUATED_NO_TRANSFER_RECORDS',forensicProcedure:'NOT_RUN'},
    meaning:'Dimension-specific checks only; no global evidence acceptance, truth, or legal-admissibility verdict.'};
  try {
    // Record commitments were independently replayed from the same raw blocks as PCC.
    for(const e of snapshot.records.values()) {
      const birth=snapshot.births.get(e.recordID), creator=birth&&identities.get(birth.txID);
      check(creator?.status==='DERIVED','CREATOR_IDENTITY_UNAVAILABLE','creator');
      check(same(e.actor,creator.actor),'RECORD_ACTOR_CREATOR_MISMATCH','creator');
      out.registrationTrail.push({recordRef:m.recordRef(e),actor:creator.actor,position:birth,
        ...(e.kind==='MATERIAL_VERSION'?{materialRef:m.materialRef(e),materialType:e.body.materialType}:{})});
    }
    out.creatorBinding='BOUND';
    for(const e of [request,packageRecord])check(snapshot.records.has(e.recordID)&&same(snapshot.records.get(e.recordID),e),'RECORD_ABSENT_FROM_HISTORY','binding');
    check(request.kind==='REVIEW_REQUEST'&&packageRecord.kind==='PACKAGE_RECORD','RECORD_KIND_MISMATCH','binding');
    const raw=inputCheck(()=>fileBytes(safeFile(packageDir,'manifest.json'),1024*1024));
    check(sha(raw)===packageRecord.body.manifestHash,'MANIFEST_HASH_MISMATCH','binding');
    check(same(packageRecord.body.requestRef,m.recordRef(request)),'PACKAGE_REQUEST_MISMATCH','binding');
    const manifest=P.parseManifestBytes(raw),basis=request.body.checkpointBasis;
    m.assertCheckpoint(basis);
    const rb=snapshot.births.get(request.recordID),pb=snapshot.births.get(packageRecord.recordID);
    check(before(rb,pb)&&BigInt(pb.block)<=BigInt(anchor.checkpoint.blockNumber),'PACKAGE_CHRONOLOGY_MISMATCH','binding');
    check(basis.channelID===actualChannel&&BigInt(basis.blockNumber)<BigInt(rb.block)&&
      snapshot.headers.find(x=>x.number===basis.blockNumber)?.hash===basis.blockHeaderHash,'BASIS_CHECKPOINT_MISMATCH','binding');
    m.assertExactShape(manifest,['formatVersion','caseID','intendedRequestRef','targetRef','checkpointBasis','scope',
      'policyRef','verifierSpecRef','checkPlan','caseConfig','profiles','materials','issues','issueEvents','suppliedFiles','tools'],'manifest');
    check(manifest.formatVersion==='LWFA_PACKAGE_2'&&manifest.caseID===request.caseID&&
      same(manifest.intendedRequestRef,m.recordRef(request)),'MANIFEST_REQUEST_MISMATCH','binding');
    for(const field of ['targetRef','checkpointBasis','scope','policyRef','verifierSpecRef','checkPlan'])
      check(same(manifest[field],request.body[field]),'MANIFEST_'+field+'_MISMATCH','binding');
    for(const field of ['materials','issues','issueEvents','suppliedFiles','tools'])check(Array.isArray(manifest[field]),'ARRAY_REQUIRED_'+field);
    const supplied=[manifest.caseConfig,...manifest.materials,...manifest.issues,...manifest.issueEvents],seen=new Set();
    for(const e of supplied) {
      check(e&&typeof e.recordID==='string'&&!seen.has(e.recordID),'INVALID_OR_DUPLICATE_SUPPLIED_RECORD');seen.add(e.recordID);
      check(snapshot.records.has(e.recordID)&&same(snapshot.records.get(e.recordID),e),'SUPPLIED_RECORD_COMMITMENT_MISMATCH','binding');
      check(BigInt(snapshot.births.get(e.recordID).block)<=BigInt(basis.blockNumber),'SUPPLIED_RECORD_AFTER_BASIS','binding');
    }
    check(manifest.caseConfig.kind==='CASE_CONFIG','CASE_CONFIG_KIND_MISMATCH');
    check(manifest.materials.every(e=>e.kind==='MATERIAL_VERSION'),'MATERIAL_KIND_MISMATCH');
    check(manifest.issues.every(e=>e.kind==='ISSUE'),'ISSUE_KIND_MISMATCH');
    check(manifest.issueEvents.every(e=>['ISSUE_RESPONSE','ISSUE_DISPOSITION'].includes(e.kind)),'ISSUE_EVENT_KIND_MISMATCH');
    check(manifest.materials.some(e=>same(m.materialRef(e),request.body.targetRef)),'TARGET_VERSION_NOT_SUPPLIED','binding');
    // Coverage is checked only for blobs belonging to SUPPLIED material records.
    // Required material dependencies and issues are not inferred.
    const want=P.blobItems(manifest.materials),paths=new Set();
    check(manifest.suppliedFiles.length===want.length,'DECLARED_BLOB_COVERAGE_MISMATCH');
    for(const item of want) {
      const entries=manifest.suppliedFiles.filter(f=>same(f.blobRef,item.blobRef));
      check(entries.length===1,'DECLARED_BLOB_REFERENCE_MISMATCH','binding');
      const f=entries[0];m.assertExactShape(f,['blobRef','relativePath','byteLength','mediaType'],'suppliedFile');
      check(f.byteLength===item.descriptor.byteLength&&f.mediaType===item.descriptor.mediaType,'BLOB_DESCRIPTOR_MISMATCH','binding');
    }
    for(const f of [...manifest.suppliedFiles,...manifest.tools]) {
      check(typeof f.relativePath==='string'&&!paths.has(f.relativePath),'DUPLICATE_OR_INVALID_FILE_PATH');paths.add(f.relativePath);
    }
    inputCheck(()=>packageInventory(packageDir,[...paths]));
    const processes=new Map(request.body.checkPlan.map(c=>[P.rkey(c.processRef),c.processRef]));
    check(manifest.tools.length===processes.size,'DECLARED_TOOL_COVERAGE_MISMATCH');
    for(const ref of processes.values()) {
      const entries=manifest.tools.filter(f=>same(f.processRef,ref)),proc=manifest.materials.find(e=>same(m.materialRef(e),ref));
      check(entries.length===1&&proc?.body.materialType==='PROCESS','DECLARED_PROCESS_TOOL_MISMATCH','binding');
      const f=entries[0];m.assertExactShape(f,['processRef','relativePath','sha256'],'tool');
      check(proc.body.data.methodSpec.executableDigest.status==='VALUE'&&f.sha256===proc.body.data.methodSpec.executableDigest.value,'TOOL_DIGEST_BINDING_MISMATCH','binding');
    }
    out.binding='MATCH';out.input='VALID';
    out.materialResults=manifest.suppliedFiles.map(f=>({...digestFile(packageDir,f,f.blobRef.sha256,f.byteLength),blobRef:f.blobRef}));
    out.toolResults=manifest.tools.map(f=>({...digestFile(packageDir,f,f.sha256),processRef:f.processRef}));
    if(presentedDisclosure!==undefined) {
      check(Array.isArray(presentedDisclosure.requiredRecords),'PRESENTED_RECORDS_ARRAY_REQUIRED');
      const ids=new Set();
      for(const row of presentedDisclosure.requiredRecords) {
        const e=row.record;check(e&&!ids.has(e.recordID),'DUPLICATE_OR_INVALID_PRESENTED_RECORD');ids.add(e.recordID);
        check(snapshot.records.has(e.recordID)&&same(snapshot.records.get(e.recordID),e),'PRESENTED_RECORD_COMMITMENT_MISMATCH','binding');
        check(same(snapshot.births.get(e.recordID),row.position),'PRESENTED_RECORD_POSITION_MISMATCH','binding');
      }
      out.presentedRecordsIntegrity='MATCH';
    }
    return out;
  } catch(e) {
    // Input format/path failures are fail-closed; programming errors must surface.
    if(!(e instanceof BaselineInputError)&&!(e instanceof io.PackageInputError)&&!(e instanceof m.LWFAError))throw e;
    out.input='REJECTED';out.reason=e.code||e.message;
    if(e.domain==='binding')out.binding='MISMATCH';
    if(e.domain==='creator')out.creatorBinding='MISMATCH';
    return out;
  }
}
module.exports={assessHashCoC};
