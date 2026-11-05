'use strict';
const {fs,path,m,ensure,sha,same,readJson,writeJson,safeFile,fileBytes,rejectedFileDigest,packageInventory,PackageInputError,inputCheck}=require('./io');
const issueContext=require('./issues');
const MANIFEST_FAILURE_CODES=Object.freeze({INVALID_JSON:'MANIFEST_INVALID_JSON',DUPLICATE_KEY:'MANIFEST_DUPLICATE_KEY',
  INVALID_UNICODE:'MANIFEST_INVALID_UNICODE',INVALID_NUMBER:'MANIFEST_INVALID_NUMBER',LIMIT_EXCEEDED:'MANIFEST_LIMIT_EXCEEDED',
  ERR_ENCODING_INVALID_ENCODED_DATA:'MANIFEST_INVALID_UTF8'});
function parseManifestBytes(bytes) {
  // Only exceptions from decoding these untrusted bytes are input diagnoses.
  // Identically named errors from trusted history or other code must propagate.
  try {return m.parseJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));}
  catch(e) {
    if(e instanceof m.LWFAError&&Object.hasOwn(MANIFEST_FAILURE_CODES,e.code))throw new PackageInputError(MANIFEST_FAILURE_CODES[e.code]);
    if(e instanceof TypeError&&e.code==='ERR_ENCODING_INVALID_ENCODED_DATA')throw new PackageInputError('MANIFEST_INVALID_UTF8');
    throw e;
  }
}
function bound(ok,code) {if(!ok)throw new PackageInputError(code,true);}
function contextRequired(ok,code,details={}) {
  if(ok)return;const e=new Error(code);e.contextFailure=true;e.details=details;throw e;
}
const rkey=ref=>`${ref.caseID}/${ref.objectID}/${ref.version}`;
function materialMap(records) {return new Map([...records.values()].filter(e=>e.kind==='MATERIAL_VERSION').map(e=>[rkey(m.materialRef(e)),e]));}
function closure(records,review) {
  const available=materialMap(records),found=new Map(),active=new Set();
  function visit(ref) {
    const key=rkey(ref);ensure(!active.has(key),'CYCLIC_BASIS');
    if(found.has(key)) {ensure(found.get(key).commitment===ref.commitment,'CONFLICTING_REFERENCE');return;}
    const e=available.get(key);ensure(e && same(m.materialRef(e),ref),'MISSING_COMMITTED_BASIS');
    active.add(key);e.body.directDeps.forEach(visit);active.delete(key);found.set(key,e);
  }
  visit(review.targetRef);review.scope.extraRoots.forEach(visit);
  for(const check of review.checkPlan)ensure(found.has(rkey(check.processRef))&&same(m.materialRef(found.get(rkey(check.processRef))),check.processRef),'CHECK_OUTSIDE_SCOPE');
  return [...found.values()].sort((a,b)=>a.recordID<b.recordID?-1:1);
}
function blobItems(materials) {
  return materials.flatMap(e=>{
    const d=e.body.data,ds=e.body.materialType==='ARTIFACT'?[d.blobDescriptor]:
      e.body.materialType==='PROCESS'?d.outputs:e.body.materialType==='REPORT'?[d.documentDescriptor]:[];
    return ds.map(descriptor=>({blobRef:{ownerVersionRef:m.materialRef(e),slotID:descriptor.slotID,sha256:descriptor.sha256},descriptor}));
  });
}
function blobKey(ref) {return `${rkey(ref.ownerVersionRef)}/${ref.slotID}`;}
function buildPackage(dir,request,caseConfig,materials,fileMap,toolMap,context={issues:[],issueEvents:[]}) {
  fs.mkdirSync(path.join(dir,'files'),{recursive:true});
  const suppliedFiles=[];
  for(const [i,item] of blobItems(materials).entries()) {
    const source=fileMap.get(blobKey(item.blobRef)),relativePath=`files/blob-${i}.bin`;
    let bytes;try {if(source)bytes=fileBytes(source);}catch(e){if(e.code!=='ENOENT')throw e;}
    if(bytes) {
      ensure(sha(bytes)===item.descriptor.sha256 && bytes.length===item.descriptor.byteLength,'EXPORT_BLOB_MISMATCH');
      fs.writeFileSync(path.join(dir,relativePath),bytes);
    } else ensure(!fs.existsSync(path.join(dir,relativePath)),'EXPORT_STALE_FILE');
    suppliedFiles.push({blobRef:item.blobRef,relativePath,byteLength:item.descriptor.byteLength,mediaType:item.descriptor.mediaType});
  }
  const tools=[],exportedTools=new Set();
  for(const [i,check] of request.body.checkPlan.entries()) {
    if(exportedTools.has(rkey(check.processRef)))continue;exportedTools.add(rkey(check.processRef));
    const proc=materials.find(e=>same(m.materialRef(e),check.processRef));ensure(proc,'EXPORT_PROCESS_MISSING');
    const digest=proc.body.data.methodSpec.executableDigest;
    ensure(digest.status==='VALUE','EXPORT_TOOL_DIGEST_NOT_DECLARED');
    const source=toolMap.get(rkey(check.processRef)),relativePath=`files/tool-${i}.js`;
    let bytes;try{if(source)bytes=fileBytes(source);}catch(e){if(e.code!=='ENOENT')throw e;}
    if(bytes){ensure(digest.value===sha(bytes),'EXPORT_TOOL_MISMATCH');fs.writeFileSync(path.join(dir,relativePath),bytes);}
    else ensure(!fs.existsSync(path.join(dir,relativePath)),'EXPORT_STALE_FILE');
    tools.push({processRef:check.processRef,relativePath,sha256:digest.value});
  }
  const manifest={formatVersion:'LWFA_PACKAGE_2',caseID:request.caseID,intendedRequestRef:m.recordRef(request),
    targetRef:request.body.targetRef,checkpointBasis:request.body.checkpointBasis,scope:request.body.scope,
    policyRef:request.body.policyRef,verifierSpecRef:request.body.verifierSpecRef,checkPlan:request.body.checkPlan,
    caseConfig,profiles:m.getSupportedProfiles(),materials,issues:context.issues,issueEvents:context.issueEvents,suppliedFiles,tools};
  writeJson(path.join(dir,'manifest.json'),manifest);return manifest;
}
function before(a,b) {return BigInt(a.block)<BigInt(b.block)||(a.block===b.block && a.index<b.index);}
function rejectionObservation(request,snapshot,checkpoint,actualChannel,attemptID,receivedBytes,failureCodes) {
  return rejectionObservationDigest(request,snapshot,checkpoint,actualChannel,attemptID,sha(receivedBytes),failureCodes);
}
function rejectionObservationFromFile(request,snapshot,checkpoint,actualChannel,attemptID,file,failureCodes) {
  return rejectionObservationDigest(request,snapshot,checkpoint,actualChannel,attemptID,rejectedFileDigest(file),failureCodes);
}
function rejectionObservationDigest(request,snapshot,checkpoint,actualChannel,attemptID,receivedDigest,failureCodes) {
  m.assertCheckpoint(checkpoint);
  ensure(typeof actualChannel==='string'&&checkpoint.channelID===actualChannel,'REJECTION_ACTUAL_CHANNEL');
  ensure(snapshot.records.has(request.recordID)&&same(snapshot.records.get(request.recordID),request),'REJECTION_REQUEST_ABSENT');
  const birth=snapshot.births.get(request.recordID),last=snapshot.headers.at(-1);
  ensure(birth&&BigInt(birth.block)<=BigInt(checkpoint.blockNumber),'REJECTION_REQUEST_OUTSIDE_HISTORY');
  ensure(last&&last.number===checkpoint.blockNumber&&last.hash===checkpoint.blockHeaderHash,'REJECTION_HISTORY_CHECKPOINT');
  return m.validateObservationBody({intendedRequestRef:m.recordRef(request),attemptID,mode:'REJECTED_INPUT',
    checkpointHistory:checkpoint,limitations:['Rejection records a reviewer observation; it does not validate the rejected basis checkpoint'],
    receivedDigest,digestKind:'RAW_INPUT',failureCodes,declaredMetadata:{}},request.caseID);
}
function verifyPackage(dir,request,packageRecord,snapshot,historyCheckpoint) {
  ensure(snapshot.records.has(request.recordID)&&snapshot.records.has(packageRecord.recordID)&&
    same(snapshot.records.get(request.recordID),request) && same(snapshot.records.get(packageRecord.recordID),packageRecord),'RECORD_ABSENT_FROM_PEER_HISTORY');
  const manifestPath=inputCheck(()=>safeFile(dir,'manifest.json')),bytes=inputCheck(()=>fileBytes(manifestPath,1024*1024));
  bound(sha(bytes)===packageRecord.body.manifestHash,'MANIFEST_HASH_MISMATCH');
  bound(same(packageRecord.body.requestRef,m.recordRef(request)),'PACKAGE_REQUEST_MISMATCH');
  const manifest=parseManifestBytes(bytes);
  const reqBorn=snapshot.births.get(request.recordID),pkgBorn=snapshot.births.get(packageRecord.recordID),basis=request.body.checkpointBasis;
  m.assertCheckpoint(basis);m.assertCheckpoint(historyCheckpoint);
  ensure(reqBorn&&pkgBorn&&snapshot.headers.at(-1)?.number===historyCheckpoint.blockNumber,'HISTORY_CHECKPOINT_POSITION');
  ensure(snapshot.headers.at(-1).hash===historyCheckpoint.blockHeaderHash,'HISTORY_CHECKPOINT_MISMATCH');
  ensure(BigInt(pkgBorn.block)<=BigInt(historyCheckpoint.blockNumber)&&before(reqBorn,pkgBorn),'REVIEW_PACKAGE_CHRONOLOGY');
  // Trusted snapshot failures are operational errors; invalid chi values in committed
  // requests are rejected inputs. The location of kappa is independent of the supplied chi.
  bound(historyCheckpoint.channelID===basis.channelID,'BASIS_CHANNEL_MISMATCH');
  bound(BigInt(reqBorn.block)>BigInt(basis.blockNumber),'BASIS_MUST_PRECEDE_REQUEST');
  bound(snapshot.headers.find(v=>v.number===basis.blockNumber)?.hash===basis.blockHeaderHash,'BASIS_CHECKPOINT_MISMATCH');
  inputCheck(()=>m.assertExactShape(manifest,['formatVersion','caseID','intendedRequestRef','targetRef','checkpointBasis','scope','policyRef',
    'verifierSpecRef','checkPlan','caseConfig','profiles','materials','issues','issueEvents','suppliedFiles','tools'],'manifest'));
  bound(manifest.formatVersion==='LWFA_PACKAGE_2' && manifest.caseID===request.caseID &&
    same(manifest.intendedRequestRef,m.recordRef(request)),'MANIFEST_REQUEST_MISMATCH');
  for(const field of ['targetRef','checkpointBasis','scope','policyRef','verifierSpecRef','checkPlan'])
    bound(same(manifest[field],request.body[field]),`MANIFEST_${field}_MISMATCH`);
  const recordsAtBasis=new Map([...snapshot.records].filter(([id])=>BigInt(snapshot.births.get(id).block)<=BigInt(basis.blockNumber)));
  const configs=[...recordsAtBasis.values()].filter(e=>e.kind==='CASE_CONFIG');ensure(configs.length===1,'CASE_CONFIG_COVERAGE');
  contextRequired(same(manifest.caseConfig,configs[0]),'PACKAGE_CASE_CONFIG_MISSING_OR_DIFFERENT',{reasonPaths:['manifest.caseConfig']});
  contextRequired(same(manifest.profiles,m.getSupportedProfiles()),'PACKAGE_PROFILES_MISSING_OR_DIFFERENT',{reasonPaths:['manifest.profiles']});
  const allow=configs[0].body.profileRefs;
  for(const profile of m.getSupportedProfiles())ensure(allow.some(p=>same(p,profile.ref)),'PROFILE_NOT_ALLOWED');
  const expected=closure(recordsAtBasis,request.body);
  contextRequired(same(manifest.materials,expected),'PACKAGE_METADATA_MISSING_OR_DIFFERENT',issueContext.coverage(manifest.materials,expected,'manifest.materials'));
  const requiredIssues=issueContext.basisContext(snapshot,request,expected);
  issueContext.requireCoverage(manifest.issues,requiredIssues.issues,'manifest.issues');
  issueContext.requireCoverage(manifest.issueEvents,requiredIssues.issueEvents,'manifest.issueEvents');
  // Independent ledger knowledge is the expected set, not a source to backfill omissions.
  const want=blobItems(expected);contextRequired(Array.isArray(manifest.suppliedFiles) && manifest.suppliedFiles.length===want.length,'PACKAGE_BLOB_DESCRIPTOR_COVERAGE',{reasonPaths:['manifest.suppliedFiles']});
  contextRequired(Array.isArray(manifest.tools) && manifest.tools.length===new Set(request.body.checkPlan.map(c=>rkey(c.processRef))).size,'PACKAGE_TOOL_COVERAGE',{reasonPaths:['manifest.tools']});
  // Required descriptors are validated before inventory checks and payload loading.
  // Context failures do not trigger package-data reads or backfilling.
  for(const item of want)contextRequired(manifest.suppliedFiles.filter(f=>f&&same(f.blobRef,item.blobRef)).length===1,
    'PACKAGE_BLOB_DESCRIPTOR_COVERAGE',{reasonPaths:[blobKey(item.blobRef)]});
  for(const f of manifest.suppliedFiles)inputCheck(()=>m.assertExactShape(f,['blobRef','relativePath','byteLength','mediaType'],'manifest.suppliedFile'));
  for(const f of manifest.tools)inputCheck(()=>m.assertExactShape(f,['processRef','relativePath','sha256'],'manifest.tool'));
  inputCheck(()=>packageInventory(dir,[...manifest.suppliedFiles,...manifest.tools].map(f=>f.relativePath)));
  const seen=new Set(),seenPaths=new Set(),materialResults=[],blobBytes=new Map();
  for(const item of want) {
    const entries=manifest.suppliedFiles.filter(f=>f&&same(f.blobRef,item.blobRef));contextRequired(entries.length===1,'PACKAGE_BLOB_DESCRIPTOR_COVERAGE',{reasonPaths:[blobKey(item.blobRef)]});
    const f=entries[0];m.assertExactShape(f,['blobRef','relativePath','byteLength','mediaType'],'manifest.suppliedFile');ensure(!seenPaths.has(f.relativePath),'DUPLICATE_PACKAGE_PATH');seenPaths.add(f.relativePath);
    contextRequired(f.byteLength===item.descriptor.byteLength && f.mediaType===item.descriptor.mediaType,'PACKAGE_DESCRIPTOR_MISMATCH',{reasonPaths:[blobKey(item.blobRef)]});
    const key=blobKey(item.blobRef);ensure(!seen.has(key),'DUPLICATE_BLOB');seen.add(key);
    let status,reason;
    try {
      const raw=inputCheck(()=>fileBytes(safeFile(dir,f.relativePath)));blobBytes.set(key,raw);
      status=sha(raw)===item.blobRef.sha256 && raw.length===f.byteLength?'HASH_MATCH':'HASH_MISMATCH';
      reason='Reviewer recomputed SHA-256 and byte length against the peer-derived descriptor';
    } catch(error) {
      if(error.code!=='ENOENT')throw error;
      status='NOT_OBTAINED';reason='Required blob was not supplied';
    }
    materialResults.push({blobRef:item.blobRef,status,reason});
  }
  contextRequired(Array.isArray(manifest.tools) && manifest.tools.length===new Set(request.body.checkPlan.map(c=>rkey(c.processRef))).size,'PACKAGE_TOOL_COVERAGE',{reasonPaths:['manifest.tools']});
  const toolBytes=new Map(),checkedTools=new Set();
  for(const check of request.body.checkPlan) {
    if(checkedTools.has(rkey(check.processRef)))continue;checkedTools.add(rkey(check.processRef));
    const entries=manifest.tools.filter(v=>v&&same(v.processRef,check.processRef));contextRequired(entries.length===1,'PACKAGE_TOOL_COVERAGE',{reasonPaths:['manifest.tools']});
    const f=entries[0],proc=expected.find(e=>same(m.materialRef(e),check.processRef));
    m.assertExactShape(f,['processRef','relativePath','sha256'],'manifest.tool');
    contextRequired(f.sha256===proc.body.data.methodSpec.executableDigest.value,'PACKAGE_TOOL_DIGEST_MISMATCH',{reasonPaths:['manifest.tools']});
    ensure(!seenPaths.has(f.relativePath),'DUPLICATE_PACKAGE_PATH');seenPaths.add(f.relativePath);
    try {const raw=inputCheck(()=>{const b=fileBytes(safeFile(dir,f.relativePath));ensure(sha(b)===f.sha256,'TOOL_HASH_MISMATCH');return b;});toolBytes.set(rkey(check.processRef),raw);}
    catch(error) {if(error.code!=='ENOENT')throw error;}
  }
  const reviewHistory=issueContext.historySummary(snapshot,request,historyCheckpoint,expected);
  const history=reviewHistory.entries.map(v=>m.recordRef(v.record));
  return {binding:'MATCH',context:'SATISFIED',contextMeaning:'Required sealed metadata equals the independently derived basis; not evidential truth',
    materialResults,blobBytes,toolBytes,materials:expected,history,reviewHistory,manifest};
}
function assessPackage(...args) {
  try {return verifyPackage(...args);} catch(e) {
    if(e.inputFailure)return {binding:e.bindingFailure?'MISMATCH':'NOT_ASSESSABLE',context:'NOT_ASSESSABLE',materialResults:[],reason:e.message,
      failureCodes:['PACKAGE_INPUT_REJECTED',e.code||e.message],observationMode:'REJECTED_INPUT'};
    if(!e.contextFailure)throw e;
    return {binding:'MATCH',context:'UNSATISFIED',materialResults:[],contextFailure:e.details,
      reason:e.message,meaning:'Required registered context was not supplied exactly; no backfill or rerun'};
  }
}
module.exports={rkey,blobKey,materialMap,closure,blobItems,buildPackage,verifyPackage,assessPackage,rejectionObservation,rejectionObservationFromFile,parseManifestBytes,MANIFEST_FAILURE_CODES,PackageInputError,inputCheck};
