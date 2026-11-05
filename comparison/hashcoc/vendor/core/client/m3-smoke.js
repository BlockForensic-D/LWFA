'use strict';
// Explicit dependency injection is for local tests only; the CLI uses live peers.
const {fs,path,m,sha,ensure,same,readJson,writeJson,fileBytes}=require('./io');
const {FabricClient}=require('./fabric'),P=require('./package'),IC=require('./issues'),IS=require('../chaincode/issues'),runner=require('./runner');
const ROOT=path.resolve(__dirname,'..');
const V=value=>({status:'VALUE',value}),U=reason=>({status:'UNKNOWN',reason}),NA=reason=>({status:'NOT_APPLICABLE',reason});
const clone=v=>m.parseJson(m.canonicalJson(v));
const normalisers={InitializeCase:m.validateInitializeInput,RegisterMaterial:m.validateRegisterInput,OpenReview:m.validateReviewInput,
 RegisterPackage:m.validatePackageInput,AppendObservation:m.validateObservationInput,RecordIssue:IS.validateIssueInput,
 RespondIssue:IS.validateResponseInput,DisposeIssue:IS.validateDispositionInput};
function keep(file,bytes) {
 fs.mkdirSync(path.dirname(file),{recursive:true});
 if(fs.existsSync(file))ensure(fs.readFileSync(file).equals(bytes),'EXISTING_BYTES_CHANGED');else fs.writeFileSync(file,bytes);
}
async function once(file,create) {if(fs.existsSync(file))return readJson(file);const v=await create();writeJson(file,v);return v;}
async function main(options={}) {
 const log=options.log||console.log;
 const work=options.work||path.join(ROOT,'results/runtime-m3-v0.5.1');fs.mkdirSync(work,{recursive:true});
 const clients=options.clients||Object.fromEntries(['AcquisitionOperator','ForensicInvestigator','AssuranceReviewer','IndependentReviewer'].map(role=>[role,new FabricClient(role)]));
 const ao=clients.AcquisitionOperator,fi=clients.ForensicInvestigator,ar=clients.AssuranceReviewer,ir=clients.IndependentReviewer;
 const execute=options.execute||runner.execute,environment=options.environment||(image=>runner.environment(image||process.env.LWFA_RUNNER_IMAGE||'hyperledger/fabric-nodeenv:2.5'));
 const outbox=path.join(work,'outbox'),records=new Map(),negatives=[],checks=[],logical=[];
 const sourceFiles=['chaincode/model.js','chaincode/issues.js','chaincode/LWFAContract.js','chaincode/state.js','chaincode/profiles.json',
 'docs/M3_ACCEPTANCE.json','client/io.js','client/fabric.js','client/history.js','client/issues.js','client/package.js','client/runner.js','client/m3-smoke.js','tools/auth-count.js'];
 const oracle=readJson(path.join(ROOT,'docs/M3_ACCEPTANCE.json'));
 const sourceHash=m.hashJson('ISSUE_SOURCE',Object.fromEntries(sourceFiles.map(f=>[f,sha(fs.readFileSync(path.join(ROOT,f)))])));
 const plan=await once(path.join(work,'plan.json'),async()=>({caseID:options.caseID||'LWFA-M3-001',sourceHash,createdAt:new Date().toISOString(),
   environment:await environment(),actors:[ao.actor,fi.actor,ar.actor,ir.actor]}));
 ensure(plan.sourceHash===sourceHash && same(plan.actors,[ao.actor,fi.actor,ar.actor,ir.actor]),'M3_PLAN_SOURCE_OR_IDENTITY_CHANGED');
 ensure(same(plan.environment,await environment(plan.environment.imageID)),'M3_ENVIRONMENT_CHANGED');
 const caseID=plan.caseID,at=V(plan.createdAt);
 function payload(method,id,field,body) {return normalisers[method]({schemaVersion:'1.0',caseID,operationID:id,recordID:id,[field]:body});}
 async function submit(client,method,id,field,body) {
   const p=payload(method,id,field,body),record=await client.submit(method,p,outbox);
   ensure(record.recordID===id && same(record.actor,client.actor),'M3_COMMITTED_RECORD_BINDING');
   records.set(id,record);logical.push(id);writeJson(path.join(work,'records',id+'.json'),record);
   log(`${method} ${id}: COMMITTED_VALID (${client.role})`);return record;
 }
 async function submitOnce(client,method,id,field,build) {
   const file=path.join(outbox,id+'.payload.json');
   const body=fs.existsSync(file)?readJson(file)[field]:await build();return submit(client,method,id,field,body);
 }
 async function material(client,id,objectID,type,data,refs,previous=null) {
   return submit(client,'RegisterMaterial',id,'material',{objectID,materialType:type,predecessorRef:previous?m.materialRef(previous):null,
     formationContext:{purpose:'Controlled M3 integration fixture',declaredRecordedTime:at},directDeps:refs,data});
 }
 const checkpoint=label=>once(path.join(work,'checkpoints',label+'.json'),()=>ir.checkpoint());
 const issue=(id,type,target,actor=ir,associated=null,reasonCode='DECLARED_CONCERN',supportRefs=[])=>submit(actor,'RecordIssue',id,'issue',{
   issueType:type,targetRef:target,reasonCode,rationale:'Registered controlled issue, not an automatic verdict',supportRefs,associatedRequestRef:associated});
 const response=(id,target,actor=fi)=>submit(actor,'RespondIssue',id,'response',{issueRef:m.recordRef(target),statement:'Attributed response; disposition remains separate',supportRefs:[]});
 const head=i=>ir.query('GetIssueHead',{caseID,issueRef:m.recordRef(i)});
 async function negative(name,client,method,p,code) {
   const before=await ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50});let rejected=false;
   try {await client.query(method,p);}catch(e){rejected=e.fabricFailure&&e.message.includes(code);if(!rejected)throw e;}
   ensure(rejected,'NEGATIVE_ACCEPTED:'+name);
   ensure(same(before,await ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50})),'NEGATIVE_STATE_CHANGED');
   negatives.push({name,expectedCode:code,result:'EXPECTED_PROPOSAL_REJECTION'});
 }
 const config=await submit(ar,'InitializeCase','case-config','config',{title:'M3 integrated issue and review history fixture',
 members:[ao,fi,ar,ir].map(c=>({actor:c.actor,roles:[c.role]})),leadInvestigator:fi.actor,reviewers:[ir.actor],profileRefs:m.getSupportedProfiles().map(p=>p.ref)});
 const incident=await material(ao,'incident-v1','incident','CONTEXT',{subtype:'INCIDENT',reportedSource:'Synthetic controlled fixture',
 incidentSummary:'Authentication counts used to test review accountability',affectedAssets:['PLC-01'],initialScope:'Synthetic fixture only',
 claimedEventTime:U('No real incident asserted'),declaredRecordedTime:at,gaps:['Not a production forensic case']},[]);
 const input=Buffer.from('result=denied\nresult=success\n'),inputPath=path.join(work,'input.log');keep(inputPath,input);
 const tool=fileBytes(runner.TOOL),originalDir=path.join(work,'original-execution');
 await once(path.join(originalDir,'execution.json'),async()=>{
   const run=await execute(plan.environment,input,tool,originalDir);ensure(!run.errorCode,'M3_ORIGINAL_EXECUTION_FAILED');
   const o=m.parseJson(run.stdout.toString());ensure(o.failedLoginCount===1&&o.successfulLoginCount===1,'M3_ORIGINAL_RESULT');
   return {sha256:sha(run.stdout),byteLength:run.stdout.length,startedAt:run.startedAt,finishedAt:run.finishedAt};
 });
 const expectedPath=path.join(originalDir,'actual-output.json'),expected=fileBytes(expectedPath),original=readJson(path.join(originalDir,'execution.json'));
 ensure(sha(expected)===original.sha256&&expected.length===original.byteLength,'M3_ORIGINAL_BYTES_CHANGED');
 const artifact=await material(ao,'artifact-v1','artifact','ARTIFACT',{incidentRef:m.materialRef(incident),acquisitionMethod:'Controlled fixture export',
 sourceDescription:'Synthetic result labels',collectionBoundary:'Two labels',claimedPerformer:V(ao.actor.clientID),blobDescriptor:{slotID:'log',sha256:sha(input),byteLength:input.length,mediaType:'text/plain'},limitations:['Synthetic fixture']},[m.materialRef(incident)]);
 const exam=await material(fi,'examination-v1','examination','PROCESS',{phase:'EXAMINATION',inputBindings:[{inputType:'BLOB',inputID:'log-input',sourceRef:m.materialRef(artifact),slotID:'log',sha256:sha(input)}],
 methodSpec:{mode:'TOOL',name:'auth-count-v1',version:V('1.0'),executableDigest:V(sha(tool))},parameters:V(runner.PARAMETERS),environment:V(plan.environment),
 outputs:[{slotID:'parsed',sha256:sha(expected),byteLength:expected.length,mediaType:'application/json'}],gaps:['Controlled synthetic fixture']},[m.materialRef(artifact)]);
 async function downstream(version,previous={}) {
   const analysis=await material(fi,`analysis-v${version}`,'analysis','PROCESS',{phase:'ANALYSIS',inputBindings:[{inputType:'BLOB',inputID:'parsed',sourceRef:m.materialRef(exam),slotID:'parsed',sha256:sha(expected)}],
   methodSpec:{mode:'MANUAL',name:'Bounded count interpretation',rationale:'Counts do not establish authorization'},parameters:NA('Manual'),environment:U('Not captured'),outputs:[],gaps:['No chronology or authorization verdict'],
   resultSummary:`Version ${version}: one denied and one successful result in synthetic input; authorization not established.`},[m.materialRef(exam)],previous.analysis);
   const finding=await material(fi,`finding-v${version}`,'finding','FINDING',{statement:analysis.body.data.resultSummary,claimType:'INTERPRETATION',rationale:'Bounded declared analysis',
   assumptions:['Source limited to fixture'],interpretationLimits:['Not a substantive truth verdict'],supportRefs:[m.materialRef(analysis)],supportStatus:'SUPPORT_DECLARED'},[m.materialRef(analysis)],previous.finding);
   const reportPath=path.join(work,`report-v${version}.md`),bytes=Buffer.from(`# M3 controlled report\n\n## Finding\n${finding.body.data.statement}\n`);keep(reportPath,bytes);
   const report=await material(fi,`report-v${version}`,'report','REPORT',{documentDescriptor:{slotID:'report',sha256:sha(bytes),byteLength:bytes.length,mediaType:'text/markdown'},
   claims:[{claimID:'counts',statement:finding.body.data.statement,findingRefs:[m.materialRef(finding)],documentLocator:'Finding'}]},[m.materialRef(finding)],previous.report);
   return {analysis,finding,report,reportPath};
 }
 const first=await downstream(1);
 const outside=await material(ao,'outside-v1','outside','CONTEXT',{...incident.body.data,incidentSummary:'Additional context outside initial review basis'},[]);
 const gap=await issue('gap-source','GAP',m.materialRef(artifact),ao);
 const specific=await issue('limitation-analysis-v1','LIMITATION',m.materialRef(first.analysis),fi);
 const unrelated=await issue('limitation-outside','LIMITATION',m.materialRef(outside),ao);
 const open=await issue('challenge-basis','CHALLENGE',m.materialRef(exam));
 const profiles=m.getReviewProfiles();
 async function review(id,target,extras=[],predecessor=null) {
   const basis=await checkpoint(id+'-basis');return submit(ar,'OpenReview',id,'review',{targetRef:m.materialRef(target),reviewerActorRef:ir.actor,
   scope:{purpose:'Bounded independent review with registered issues',extraRoots:extras},checkpointBasis:basis,policyRef:profiles.policy.ref,verifierSpecRef:profiles.verifier.ref,
   checkPlan:[{checkID:'rerun-examination',checkType:'RERUN_PROCESS',processRef:m.materialRef(exam),inputBindings:exam.body.data.inputBindings,expectedOutputs:exam.body.data.outputs,
     comparator:'JSON_CANONICAL_EQUAL',requiredEnvironment:exam.body.data.environment}],predecessorRequestRef:predecessor?m.recordRef(predecessor):null});
 }
 const request=await review('request-v1',first.report);
 const requestRef=m.recordRef(request),fileMap=new Map([[P.blobKey({ownerVersionRef:m.materialRef(artifact),slotID:'log'}),inputPath],
 [P.blobKey({ownerVersionRef:m.materialRef(exam),slotID:'parsed'}),expectedPath],[P.blobKey({ownerVersionRef:m.materialRef(first.report),slotID:'report'}),first.reportPath]]);
 // Exporter list is assembled from its own committed reads. Org3 derives obligations separately from blocks.
 const material1=[incident,artifact,exam,first.analysis,first.finding,first.report];
 const context1={issues:[open,gap,specific].sort((a,b)=>a.recordID.localeCompare(b.recordID)),issueEvents:[]};
 async function build(id,req,materials,context,files) {
   const dir=path.join(work,id);if(!fs.existsSync(path.join(dir,'manifest.json'))) {
     const own=await Promise.all(materials.map(e=>fi.record(caseID,e.recordID)));
     const ownedIssues=await Promise.all(context.issues.map(e=>fi.record(caseID,e.recordID)));
     const ownedEvents=await Promise.all(context.issueEvents.map(e=>fi.record(caseID,e.recordID)));
     P.buildPackage(dir,req,config,P.closure(new Map(own.map(e=>[e.recordID,e])),req.body),files,new Map([[P.rkey(m.materialRef(exam)),runner.TOOL]]),
       {issues:ownedIssues.sort((a,b)=>a.recordID<b.recordID?-1:1),issueEvents:ownedEvents.sort((a,b)=>a.recordID<b.recordID?-1:1)});
   }
   const record=await submit(fi,'RegisterPackage',id,'package',{requestRef:m.recordRef(req),manifestHash:sha(fileBytes(path.join(dir,'manifest.json'),1024*1024)),
     formatVersion:'LWFA_PACKAGE_2',declaredExporter:V('LWFA M3 controlled exporter 0.5.1')});return {dir,record};
 }
 async function assess(id,req,bundle,executeCheck=true) {
   const ownReq=await ir.record(caseID,req.recordID),ownPackage=await ir.record(caseID,bundle.record.recordID),cutoff=await checkpoint(id+'-history');
   const snap=await ir.snapshot(caseID,cutoff,path.join(work,id,'org3-history'));
   const result=P.assessPackage(bundle.dir,ownReq,ownPackage,snap,cutoff);
   const check=ownReq.body.checkPlan[0];let outcome;
   const obFile=path.join(outbox,id+'.payload.json');
   if(fs.existsSync(obFile))outcome=readJson(obFile).observation.checkResults[0];
   else if(result.context==='SATISFIED'&&executeCheck) {
     const proc=result.materials.find(e=>same(m.materialRef(e),check.processRef));
     const inputRef={ownerVersionRef:check.inputBindings[0].sourceRef,slotID:check.inputBindings[0].slotID};
     outcome=runner.rerun(proc,check,result.blobBytes.get(P.blobKey(inputRef)),result.blobBytes.get(P.blobKey({ownerVersionRef:check.processRef,slotID:'parsed'})),
       result.toolBytes.get(P.rkey(check.processRef)),path.join(work,id,'reviewer-execution'),execute);
   } else outcome={checkID:check.checkID,status:'NOT_RUN',reason:'Mandatory issue context not supplied; execution was not attempted'};
   if(result.context==='SATISFIED'&&executeCheck)ensure(outcome.status==='EXECUTED_MATCH','M3_RERUN_EXPECTATION');
   const observation=await submit(ir,'AppendObservation',id,'observation',{intendedRequestRef:m.recordRef(ownReq),attemptID:id,mode:'CHECKS',checkpointHistory:cutoff,
     limitations:['One synthetic scenario on a single host','TLS-authenticated peer validation metadata is trusted; no independent signature/consensus revalidation',
       'Execution and disposition are attributed records, not substantive truth',...(result.contextFailure?.reasonPaths||[])],
     packageRef:m.recordRef(ownPackage),manifestHash:ownPackage.body.manifestHash,binding:result.binding,context:result.context,materialResults:result.materialResults,checkResults:[outcome]});
   writeJson(path.join(work,id,'assessment.json'),{binding:result.binding,context:result.context,contextFailure:result.contextFailure||null,
     materialResults:result.materialResults,procedure:outcome.status,issueHeads:result.reviewHistory?.issueHeads||[],observationRef:m.recordRef(observation)});
   return {result,observation,snapshot:snap};
 }
 const full=await build('package-full-v1',request,material1,context1,fileMap),good=await assess('observation-full-v1',request,full);
 ensure(good.result.context==='SATISFIED'&&good.result.reviewHistory.issueHeads.some(h=>h.issueRef.recordID===open.recordID&&h.status==='OPEN'),'OPEN_CHALLENGE_MUST_NOT_FAIL_CONTEXT');
 checks.push({name:'complete-package-with-open-challenge',result:'SATISFIED',procedure:'EXECUTED_MATCH'});
 // Both the manifest and its registered hash omit one mandatory issue.
 const omittedDir=path.join(work,'package-omitted-v1');
 if(!fs.existsSync(path.join(omittedDir,'manifest.json'))) {
   fs.cpSync(full.dir,omittedDir,{recursive:true});const mf=readJson(path.join(omittedDir,'manifest.json'));
   mf.issues=mf.issues.filter(e=>e.recordID!==gap.recordID);writeJson(path.join(omittedDir,'manifest.json'),mf);
 }
 const omittedRecord=await submit(fi,'RegisterPackage','package-omitted-v1','package',{...full.record.body,
   manifestHash:sha(fileBytes(path.join(omittedDir,'manifest.json'),1024*1024))});
 const omitted=await assess('observation-omitted-v1',request,{dir:omittedDir,record:omittedRecord},false);
 ensure(omitted.result.binding==='MATCH'&&omitted.result.context==='UNSATISFIED'&&omitted.result.contextFailure.missing.includes(gap.recordID),'OMISSION_EXPECTATION');
 checks.push({name:'registered-consistent-issue-omission',binding:'MATCH',context:'UNSATISFIED',missing:gap.recordID,procedure:'NOT_RUN'});
 const rejected=await submitOnce(ir,'AppendObservation','observation-rejected','observation',async()=>({intendedRequestRef:requestRef,attemptID:'malformed-attempt',mode:'REJECTED_INPUT',
 checkpointHistory:await checkpoint('rejected-history'),limitations:['Controlled malformed input'],receivedDigest:sha(Buffer.from('{malformed-package')),
 digestKind:'RAW_INPUT',failureCodes:['MALFORMED_PACKAGE'],declaredMetadata:{}}));
 const scopeIssue=await issue('challenge-scope','CHALLENGE',requestRef,ir,requestRef,'SCOPE_INADEQUATE',[m.materialRef(outside)]);
 const rsp1=await response('response-scope-1',scopeIssue,ar);
 // Expected value is deliberately the sequence after only the first response.
 const rsp2=await response('response-scope-2',scopeIssue,ar);
 await negative('stale-disposition',ir,'DisposeIssue',payload('DisposeIssue','negative-stale','disposition',{issueRef:m.recordRef(scopeIssue),expectedIssueSeq:rsp1.body.issueSeq,
   disposition:'ADDRESSED',rationale:'Deliberately stale test',supportRefs:[]}),'STALE_ISSUE_BASIS');
 const disp=await submitOnce(ir,'DisposeIssue','disposition-scope','disposition',async()=>({issueRef:m.recordRef(scopeIssue),expectedIssueSeq:(await head(scopeIssue)).lastEventSeq,
 disposition:'DISAGREEMENT',rationale:'Scope disagreement remains explicitly attributed; successor request evaluates expanded basis',supportRefs:[]}));
 const lateResponse=await response('response-after-disposition',scopeIssue,ar);
 const after=await head(scopeIssue);ensure(after.status==='DISAGREEMENT'&&same(after.latestDispositionRef,m.recordRef(disp)),'RESPONSE_REOPENED_CHALLENGE');
 // Explicit replay of an already committed operation after a later event.
 const beforeRetry=await ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50});
 const recovered=await ir.submit('DisposeIssue',readJson(path.join(outbox,'disposition-scope.payload.json')),outbox);
 ensure(same(recovered,disp)&&same(beforeRetry,await ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50})),'DISPOSITION_RETRY_CHANGED_STATE');
 checks.push({name:'response-not-disposition-and-retry',status:after.status,lastEventSeq:after.lastEventSeq,result:'PASS'});
 const withdrawal=await submitOnce(ir,'DisposeIssue','withdraw-basis','disposition',async()=>({issueRef:m.recordRef(open),expectedIssueSeq:(await head(open)).lastEventSeq,
 disposition:'WITHDRAWN',rationale:'Submitter withdraws this controlled challenge without deleting history',supportRefs:[]}));
 const lateGap=await issue('gap-after-chi','GAP',m.materialRef(artifact),ao);
 const second=await downstream(2,first);
 const next=await review('request-v2',second.report,[m.materialRef(outside)],request);
 fileMap.set(P.blobKey({ownerVersionRef:m.materialRef(second.report),slotID:'report'}),second.reportPath);
 const context2={issues:[open,gap,lateGap,unrelated],issueEvents:[withdrawal]};
 const full2=await build('package-full-v2',next,[incident,artifact,exam,second.analysis,second.finding,second.report,outside],context2,fileMap);
 const good2=await assess('observation-full-v2',next,full2);
 ensure(good2.result.manifest.issues.some(e=>e.recordID===gap.recordID)&&!good2.result.manifest.issues.some(e=>e.recordID===specific.recordID),'VERSION_ISSUE_APPLICABILITY');
 checks.push({name:'version-specific-issue-and-shared-ancestor',retained:gap.recordID,excluded:specific.recordID,result:'PASS'});
 const linked=await issue('challenge-linked-late','CHALLENGE',m.materialRef(first.report),ir,requestRef);
 const finalCheckpoint=await checkpoint('final-history'),snap=await ir.snapshot(caseID,finalCheckpoint,path.join(work,'final-org3-history'));
 const req1=await ir.record(caseID,request.recordID),materialsAtBasis=P.closure(IC.at(snap,req1.body.checkpointBasis),req1.body);
 const summary=IC.historySummary(snap,req1,finalCheckpoint,materialsAtBasis);
 ensure(!summary.entries.some(e=>e.record.recordID===lateGap.recordID)&&summary.entries.some(e=>e.record.recordID===linked.recordID),'CHI_KAPPA_RELEVANCE');
 writeJson(path.join(work,'history-full.json'),summary);
 const historyChecks=[];
 for(const id of [rejected.recordID,omitted.observation.recordID,rsp2.recordID]) {
   const shown=clone(summary);shown.entries=shown.entries.filter(e=>e.record.recordID!==id);
   const result=IC.verifyHistorySummary(shown,snap,req1,finalCheckpoint,materialsAtBasis);
   ensure(result.historyStatus==='UNSATISFIED'&&result.missing.includes(id),'HISTORY_OMISSION_EXPECTATION');
   writeJson(path.join(work,'history-omission-'+id+'.json'),{presented:shown,result});historyChecks.push({omitted:id,result:result.historyStatus});
 }
 const replayed=summary.issueHeads.find(h=>h.issueRef.recordID===scopeIssue.recordID);
 ensure(same(replayed,await head(scopeIssue)),'ISSUE_HEAD_REPLAY_MISMATCH');
 const baseDisposition={issueRef:m.recordRef(scopeIssue),expectedIssueSeq:after.lastEventSeq,disposition:'ADDRESSED',rationale:'Negative test',supportRefs:[]};
 await negative('wrong-disposition-actor',fi,'DisposeIssue',payload('DisposeIssue','negative-actor','disposition',baseDisposition),'UNAUTHORIZED');
 await negative('wrong-withdrawal-actor',fi,'DisposeIssue',payload('DisposeIssue','negative-withdraw','disposition',{...baseDisposition,disposition:'WITHDRAWN'}),'UNAUTHORIZED');
 await negative('wrong-response-actor',ao,'RespondIssue',payload('RespondIssue','negative-response','response',{issueRef:m.recordRef(scopeIssue),statement:'Unauthorized response',supportRefs:[]}),'UNAUTHORIZED');
 await negative('nonchallenge-disposition',ir,'DisposeIssue',payload('DisposeIssue','negative-gap','disposition',{...baseDisposition,issueRef:m.recordRef(gap),expectedIssueSeq:1}),'INVALID_ISSUE_TYPE');
 const b={...gap.body,targetRef:{...gap.body.targetRef,objectID:'missing'}};
 await negative('nonexistent-target',ao,'RecordIssue',payload('RecordIssue','negative-target','issue',b),'INVALID_REFERENCE');
 await negative('duplicate-issue-record',ao,'RecordIssue',{...payload('RecordIssue','negative-duplicate','issue',gap.body),recordID:gap.recordID},'DUPLICATE_ID');
 const retained=await ir.query('GetMaterialVersion',{caseID,objectID:'report',version:1});ensure(same(retained,first.report),'M3_OLD_REPORT_CHANGED');
 const journal=await ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50});
 const EXPECTED_MUTATIONS=oracle.businessMutations;
 ensure(plan.caseID===(options.caseID||oracle.caseID)&&same(logical,oracle.operations),'M3_PREDECLARED_WORKFLOW_MISMATCH');
 ensure(same(negatives.map(n=>({name:n.name,code:n.expectedCode})),oracle.negativeProposals),'M3_NEGATIVE_CATALOG_MISMATCH');
 ensure(same(historyChecks.map(v=>v.omitted),oracle.historyOmissionControls),'M3_HISTORY_CATALOG_MISMATCH');
 ensure(logical.length===EXPECTED_MUTATIONS && journal.headSequence===EXPECTED_MUTATIONS && journal.items.length===EXPECTED_MUTATIONS && !journal.hasMore,'M3_JOURNAL_COUNT');
 ensure(same(journal.items.map(e=>e.recordRef.recordID),logical),'M3_JOURNAL_ORDER');
 const result={release:'0.5.1',caseID,chaincode:ir.name,headSequence:journal.headSequence,
   coverage:checks,historyChecks,negativeProposals:negatives,issueHeads:summary.issueHeads,
   historyVerification:IC.verifyHistorySummary(summary,snap,req1,finalCheckpoint,materialsAtBasis).historyStatus,
   oldReportBinding:'PRESERVED',reruns:['EXECUTED_MATCH','EXECUTED_MATCH'],
   trustModel:'TLS_AUTHENTICATED_ORG3_PEER_WITH_VALIDATION_METADATA',scope:'ONE_SYNTHETIC_SCENARIO_M3_CONTROLLED_VARIATIONS',
   limits:['Not final research evaluation','No independent consensus validation','No proof of unrecorded events','Live MVCC races and crash injection not claimed'],result:'PASS'};
 writeJson(path.join(work,'summary.json'),result);writeJson(path.join(work,'journal.json'),journal);
 log(JSON.stringify(result,null,2));log('PASS: M3 controlled runtime smoke, not final PCC evaluation');return result;
}
if(require.main===module)main().catch(e=>{console.error(e.stack);process.exitCode=1;});
module.exports={main,normalisers};
