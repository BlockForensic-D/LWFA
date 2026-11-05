'use strict';
// REF-LIFECYCLE: manifest-directed verification on a matched common ledger.
// Does not call LWFA closure(), basisContext(), historySummary(), or verifyPackage().
const {fs,path,m,IS,ensure,same,sha,readJson,safeFile,fileBytes,packageInventory,inputCheck}=require('../experiments/common');
function record(e,snapshot){m.verifyEnvelopeCommitment(e);ensure(same(snapshot.records.get(e.recordID),e),'REF_RECORD_NOT_COMMITTED');
 if(e.kind==='MATERIAL_VERSION')m.validateMaterialBody(e.body,e.caseID);
 if(e.kind==='ISSUE')IS.validateIssueBody(e.body,e.caseID);
 if(e.kind==='ISSUE_RESPONSE')IS.validateResponseBody(e.body,e.caseID,true);
 if(e.kind==='ISSUE_DISPOSITION')IS.validateDispositionBody(e.body,e.caseID,true);
}
function verifyPackage(dir,request,packageRecord,snapshot){
 const bytes=fileBytes(safeFile(dir,'manifest.json'),1024*1024);ensure(sha(bytes)===packageRecord.body.manifestHash,'MANIFEST_HASH_MISMATCH');
 record(request,snapshot);record(packageRecord,snapshot);let x;
 try{x=m.parseJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch(e){if(e.code==='INVALID_JSON')throw new Error('MANIFEST_INVALID_JSON');throw e;}
 ensure(x.formatVersion==='LWFA_PACKAGE_2'&&x.caseID===request.caseID,'REF_FORMAT_CASE');
 ensure(same(x.intendedRequestRef,m.recordRef(request))&&same(packageRecord.body.requestRef,m.recordRef(request)),'PACKAGE_REQUEST_MISMATCH');
 for(const k of ['targetRef','checkpointBasis','scope','policyRef','verifierSpecRef','checkPlan'])ensure(same(x[k],request.body[k]),`MANIFEST_${k}_MISMATCH`);
 m.assertExactShape(x,['formatVersion','caseID','intendedRequestRef','targetRef','checkpointBasis','scope','policyRef','verifierSpecRef','checkPlan','caseConfig','profiles','materials','issues','issueEvents','suppliedFiles','tools'],'manifest');
 record(x.caseConfig,snapshot);ensure(same(x.profiles,m.getSupportedProfiles()),'REF_PROFILE_MISMATCH');
 const supplied=[...x.materials,...x.issues,...x.issueEvents],ids=new Set();for(const e of supplied){ensure(e.caseID===request.caseID&&!ids.has(e.recordID),'REF_DUPLICATE_OR_FOREIGN_RECORD');ids.add(e.recordID);record(e,snapshot);}
 // Supplied provenance is queryable and exact references are checked. Omitted
 // same-case records are not promoted to package completeness obligations.
 const mats=new Map(x.materials.map(e=>[m.canonicalJson(m.materialRef(e)),e]));
 ensure(mats.has(m.canonicalJson(request.body.targetRef)),'REF_TARGET_NOT_SUPPLIED');
 const materialResults=[],blobBytes=new Map(),toolBytes=new Map(),paths=new Set(),blobs=new Set(),tools=new Set();
 packageInventory(dir,[...x.suppliedFiles,...x.tools].map(f=>f.relativePath));
 for(const f of x.suppliedFiles){m.assertExactShape(f,['blobRef','relativePath','byteLength','mediaType'],'file');m.assertBlobRef(f.blobRef,request.caseID);
 const owner=mats.get(m.canonicalJson(f.blobRef.ownerVersionRef));ensure(owner,'REF_OWNER_NOT_SUPPLIED');const d=owner.body.data;
 const ds=owner.body.materialType==='ARTIFACT'?[d.blobDescriptor]:owner.body.materialType==='REPORT'?[d.documentDescriptor]:owner.body.materialType==='PROCESS'?d.outputs:[];
 const descriptor=ds.find(v=>v.slotID===f.blobRef.slotID);ensure(descriptor&&descriptor.sha256===f.blobRef.sha256&&descriptor.byteLength===f.byteLength&&descriptor.mediaType===f.mediaType,'REF_DESCRIPTOR_MISMATCH');
 const key=`${owner.caseID}/${owner.body.objectID}/${owner.body.version}/${f.blobRef.slotID}`;ensure(!paths.has(f.relativePath)&&!blobs.has(key),'REF_DUPLICATE_FILE');paths.add(f.relativePath);blobs.add(key);
 let status;try{const raw=fileBytes(safeFile(dir,f.relativePath));blobBytes.set(key,raw);status=sha(raw)===descriptor.sha256&&raw.length===descriptor.byteLength?'HASH_MATCH':'HASH_MISMATCH';}catch(e){if(e.code!=='ENOENT')throw e;status='NOT_OBTAINED';}
 materialResults.push({blobRef:f.blobRef,status,reason:'Manifest-directed hash/size check against committed supplied descriptor'});
 }
 for(const f of x.tools){m.assertExactShape(f,['processRef','relativePath','sha256'],'tool');const proc=mats.get(m.canonicalJson(f.processRef));
 ensure(proc&&proc.body.materialType==='PROCESS'&&proc.body.data.methodSpec.executableDigest.value===f.sha256,'REF_TOOL_BINDING');
 const key=`${proc.caseID}/${proc.body.objectID}/${proc.body.version}`;ensure(!paths.has(f.relativePath)&&!tools.has(key),'REF_DUPLICATE_TOOL');paths.add(f.relativePath);tools.add(key);
 try{const raw=fileBytes(safeFile(dir,f.relativePath));ensure(sha(raw)===f.sha256,'TOOL_HASH_MISMATCH');toolBytes.set(key,raw);}catch(e){if(e.code!=='ENOENT')throw e;}
 }
 return {system:'REF-LIFECYCLE',binding:'MATCH',context:'NOT_EVALUATED',historyCoverage:'NOT_EVALUATED',materialResults,materials:x.materials,blobBytes,toolBytes,manifest:x,
 limitation:'No independent scope-derived obligation set; NOT_EVALUATED is not a scope acceptance'};
}
function verifyHistory(presented,snapshot){const seen=new Set();for(const entry of presented.entries){const e=entry.record;ensure(!seen.has(e.recordID),'REF_DUPLICATE_HISTORY');seen.add(e.recordID);record(e,snapshot);}
 return {recordIntegrity:'MATCH',historyStatus:'NOT_EVALUATED',checkedSupplied:seen.size};}
function assessPackage(...args){
 try{return inputCheck(()=>verifyPackage(...args));}
 catch(e){
  if(e.inputFailure||/^(REF_|MANIFEST_|PACKAGE_REQUEST_|TOOL_HASH_)/.test(e.message))
    return {binding:/^(MANIFEST_(HASH|scope|targetRef|checkpointBasis|policyRef|verifierSpecRef|checkPlan)_MISMATCH|PACKAGE_REQUEST_MISMATCH|REF_FORMAT_CASE)$/.test(e.message)?'MISMATCH':'NOT_ASSESSABLE',
      context:'NOT_EVALUATED',materialResults:[],reason:e.message,observationMode:'REJECTED_INPUT'};
  throw e;
 }
}
module.exports={verifyPackage,verifyHistory,assessPackage};
