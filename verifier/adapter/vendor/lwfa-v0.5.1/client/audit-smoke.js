'use strict';
// Controlled runtime acceptance for the audit corrections, using the existing
// infrastructure. The default client obtains authenticated Org3 peer snapshots.
const {fs,path,m,ensure,sha,same,readJson,writeJson,fileBytes}=require('./io');
const {FabricClient}=require('./fabric'),P=require('./package'),M3=require('./m3-smoke');
const ROOT=path.resolve(__dirname,'..');
async function main(options={}){
 const work=options.work||path.join(ROOT,'results/runtime-audit-v0.5.1'),caseID='LWFA-AUDIT-051';
 const clients=options.clients||Object.fromEntries(['AcquisitionOperator','ForensicInvestigator','AssuranceReviewer','IndependentReviewer'].map(role=>[role,new FabricClient(role)]));
 const fi=clients.ForensicInvestigator,ar=clients.AssuranceReviewer,ir=clients.IndependentReviewer,outbox=path.join(work,'outbox');
 const seed=path.join(work,'seed'),seedSummary=path.join(seed,'summary.json');
 if(!fs.existsSync(seedSummary))await M3.main({...options,clients,caseID,work:seed});
 ensure(readJson(seedSummary).caseID===caseID&&readJson(seedSummary).result==='PASS','AUDIT_SEED_NOT_READY');
 const old=await ir.record(caseID,'request-v1'),outcomes=[];
 async function submit(c,method,id,field,body){
  return c.submit(method,{schemaVersion:'1.0',caseID,operationID:id,recordID:id,[field]:body},outbox);
 }
 async function cutoff(id){
  const file=path.join(work,id+'-checkpoint.json');
  if(!fs.existsSync(file))writeJson(file,await ir.checkpoint());
  const cp=readJson(file),snap=await ir.snapshot(caseID,cp,path.join(work,id+'-history'));return {cp,snap};
 }
 for(const mode of ['future','foreign']){
  const requestBody=m.parseJson(m.canonicalJson(old.body));
  if(mode==='future')requestBody.checkpointBasis.blockNumber='18446744073709551615';
  else requestBody.checkpointBasis.channelID='deliberately-invalid-channel';
  const request=await submit(ar,'OpenReview','audit-request-'+mode,'review',requestBody);
  const {cp,snap}=await cutoff('audit-'+mode);
  const body=P.rejectionObservation(request,snap,cp,ir.channel,'audit-'+mode,Buffer.from(m.canonicalJson(requestBody)),['INVALID_BASIS_CHECKPOINT']);
  const observed=await submit(ir,'AppendObservation','audit-rejection-'+mode,'observation',body);
  ensure(observed.body.mode==='REJECTED_INPUT','AUDIT_REJECTION_NOT_RECORDED');
  outcomes.push({condition:mode+'-basis',requestRef:m.recordRef(request),observationRef:m.recordRef(observed),result:'PASS'});
 }
 const packageDir=path.join(work,'omitted-material','package'),mf=path.join(packageDir,'manifest.json');
 if(!fs.existsSync(mf)){
  fs.mkdirSync(path.dirname(packageDir),{recursive:true});fs.cpSync(path.join(seed,'package-full-v1'),packageDir,{recursive:true});
  const manifest=readJson(mf);manifest.materials=manifest.materials.filter(e=>e.body.materialType!=='ARTIFACT');writeJson(mf,manifest);
 }
 const pkg=await submit(fi,'RegisterPackage','audit-omitted-material','package',{requestRef:m.recordRef(old),
  manifestHash:sha(fileBytes(mf,1024*1024)),formatVersion:'LWFA_PACKAGE_2',declaredExporter:{status:'VALUE',value:'Audit regression fixture'}});
 const {cp,snap}=await cutoff('audit-omitted-material'),result=P.assessPackage(packageDir,old,pkg,snap,cp);
 ensure(result.binding==='MATCH'&&result.context==='UNSATISFIED'&&result.contextFailure.missing.length>0,'AUDIT_METADATA_DIAGNOSIS');
 const ob=await submit(ir,'AppendObservation','audit-metadata-observation','observation',{intendedRequestRef:m.recordRef(old),
  attemptID:'audit-metadata',mode:'CHECKS',checkpointHistory:cp,limitations:result.contextFailure.reasonPaths,
  packageRef:m.recordRef(pkg),manifestHash:pkg.body.manifestHash,binding:'MATCH',context:'UNSATISFIED',materialResults:[],
  checkResults:old.body.checkPlan.map(c=>({checkID:c.checkID,status:'NOT_RUN',reason:'Required material metadata omitted; no backfill'}))});
 outcomes.push({condition:'registered-material-omission',observationRef:m.recordRef(ob),result:'PASS',assessment:result});
 const summary={release:'0.5.1',caseID,chaincode:ir.name,result:'PASS',outcomes,
  classification:'CONTROLLED_AUDIT_REGRESSION_NOT_FINAL_RESEARCH',trustModel:'TLS_AUTHENTICATED_ORG3_PEER_VALIDATION_METADATA'};
 writeJson(path.join(work,'summary.json'),summary);(options.log||console.log)(JSON.stringify(summary,null,2));return summary;
}
if(require.main===module)main().catch(e=>{console.error(e.stack);process.exitCode=1;});
module.exports={main};
