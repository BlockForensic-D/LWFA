'use strict';
// One synthetic scenario, two controlled versions; no network reset/enrollment.
const {fs,path,m,ensure,sha,readJson,writeJson,same,fileBytes}=require('./io');
const {FabricClient}=require('./fabric');const pkg=require('./package');const runner=require('./runner');
const ROOT=path.resolve(__dirname,'..');
const WORK=path.join(ROOT,'results/runtime-m2-regression-v0.5.1');
const VALUE=value=>({status:'VALUE',value});const UNKNOWN=reason=>({status:'UNKNOWN',reason});
const NA=reason=>({status:'NOT_APPLICABLE',reason});
function once(file,build) {if(fs.existsSync(file))return readJson(file);const value=build();writeJson(file,value);return value;}
function keepBytes(file,bytes) {
  fs.mkdirSync(path.dirname(file),{recursive:true});
  if(fs.existsSync(file))ensure(fs.readFileSync(file).equals(bytes),'EXISTING_FIXTURE_BYTES_DIFFER');
  else fs.writeFileSync(file,bytes);
}
function normalise(method,payload) {
  return ({InitializeCase:m.validateInitializeInput,RegisterMaterial:m.validateRegisterInput,OpenReview:m.validateReviewInput,
    RegisterPackage:m.validatePackageInput,AppendObservation:m.validateObservationInput})[method](payload);
}
async function main() {
  fs.mkdirSync(WORK,{recursive:true});
  const ao=new FabricClient('AcquisitionOperator'),fi=new FabricClient('ForensicInvestigator'),
    ar=new FabricClient('AssuranceReviewer'),ir=new FabricClient('IndependentReviewer');
  const baseline=new FabricClient('ForensicInvestigator',{name:'lwfaContract'});
  const oldBefore=baseline.query('ListCaseJournal',{caseID:'LWFA-SMOKE-001',afterSequence:0,limit:50});
  ensure(oldBefore.headSequence===10,'BASELINE_JOURNAL_CHANGED');
  const sourceHash=m.hashJson('CLIENT_RELEASE',Object.fromEntries(['chaincode/model.js','chaincode/LWFAContract.js',
    'chaincode/state.js','chaincode/profiles.json','client/io.js','client/smoke.js','client/runner.js','client/package.js','client/history.js','client/fabric.js','tools/auth-count.js']
    .map(f=>[f,sha(fs.readFileSync(path.join(ROOT,f)))])));
  const plan=once(path.join(WORK,'plan.json'),()=>({caseID:'LWFA-RERUN-REGRESSION-005',createdAt:new Date().toISOString(),
    sourceHash,environment:runner.environment(process.env.LWFA_RUNNER_IMAGE||'hyperledger/fabric-nodeenv:2.5'),actors:[ao.actor,fi.actor,ar.actor,ir.actor]}));
  ensure(plan.sourceHash===sourceHash && same(plan.actors,[ao.actor,fi.actor,ar.actor,ir.actor]),'RUN_PLAN_SOURCE_OR_IDENTITIES_CHANGED');
  ensure(same(plan.environment,runner.environment(plan.environment.imageID)),'RUN_IMAGE_CHANGED');
  const caseID=plan.caseID,at=VALUE(plan.createdAt),outbox=path.join(WORK,'outbox');
  const input=Buffer.from('timestamp=2026-09-15T08:50:00.000Z\nasset=PLC-01\nevent=failed-login\nresult=denied\n\ntimestamp=2026-09-15T08:51:12.000Z\nasset=PLC-01\nevent=administrative-login\nresult=success\n');
  const inputPath=path.join(WORK,'fixture.log');keepBytes(inputPath,input);
  const tool=fileBytes(runner.TOOL);const originalDir=path.join(WORK,'original-execution');
  let original;
  if(fs.existsSync(path.join(originalDir,'original.json')))original=readJson(path.join(originalDir,'original.json'));
  else {
    const run=runner.execute(plan.environment,input,tool,originalDir);ensure(!run.errorCode,'ORIGINAL_EXECUTION_FAILED');
    const count=m.parseJson(run.stdout.toString());ensure(count.failedLoginCount===1 && count.successfulLoginCount===1,'ORIGINAL_RESULT_UNEXPECTED');
    original={sha256:sha(run.stdout),byteLength:run.stdout.length,startedAt:run.startedAt,finishedAt:run.finishedAt};
    writeJson(path.join(originalDir,'original.json'),original);
  }
  const originalPath=path.join(originalDir,'actual-output.json');ensure(sha(fileBytes(originalPath))===original.sha256,'ORIGINAL_OUTPUT_CHANGED');
  function submit(client,method,id,field,body) {
    const payload=normalise(method,{schemaVersion:'1.0',caseID,operationID:id,recordID:id,[field]:body});
    const result=client.submit(method,payload,outbox);writeJson(path.join(WORK,'records',`${id}.json`),result);
    console.log(`${method} ${id}: COMMITTED_VALID (${client.role})`);return result;
  }
  function material(client,id,type,data,deps,version=1,previous=null) {
    return submit(client,'RegisterMaterial',`${id}-v${version}`,'material',{objectID:id,materialType:type,
      predecessorRef:previous?m.materialRef(previous):null,formationContext:{purpose:`Controlled LWFA ${type.toLowerCase()} smoke fixture`,declaredRecordedTime:at},
      directDeps:deps,data});
  }
  const caseConfig=submit(ar,'InitializeCase','case-config','config',{title:'Controlled LWFA rerun scenario',
    members:[ao,fi,ar,ir].map(c=>({actor:c.actor,roles:[c.role]})),leadInvestigator:fi.actor,reviewers:[ir.actor],
    profileRefs:m.getSupportedProfiles().map(p=>p.ref)});
  const incident=material(ao,'incident','CONTEXT',{subtype:'INCIDENT',reportedSource:'Synthetic fixture',
    incidentSummary:'Two authentication results for a controlled protocol test',affectedAssets:['PLC-01'],
    initialScope:'Synthetic fixture only',claimedEventTime:UNKNOWN('No production event is asserted'),
    declaredRecordedTime:at,gaps:['Not evidence from a production system']},[]);
  const incRef=m.materialRef(incident);
  const artifact=material(ao,'artifact','ARTIFACT',{incidentRef:incRef,acquisitionMethod:'Controlled fixture creation',
    sourceDescription:'Synthetic authentication labels',collectionBoundary:'Two declared labels',claimedPerformer:VALUE(ao.actor.clientID),
    blobDescriptor:{slotID:'log',sha256:sha(input),byteLength:input.length,mediaType:'text/plain'},limitations:['Synthetic integration fixture']},[incRef]);
  const artifactRef=m.materialRef(artifact),profiles=m.getReviewProfiles(),outcomes=[],negatives=[];
  const previous={};let reportV1;
  for(const version of [1,2]) {
    const vdir=path.join(WORK,`version-${version}`);fs.mkdirSync(vdir,{recursive:true});
    const expectedPath=path.join(vdir,'expected.json');
    // v2 is intentionally false at registration, not altered after commitment.
    keepBytes(expectedPath,version===1?fileBytes(originalPath):Buffer.from('{"failedLoginCount":99,"successfulLoginCount":1}\n'));
    const expectedBytes=fileBytes(expectedPath);
    const exam=material(fi,'examination','PROCESS',{phase:'EXAMINATION',
      inputBindings:[{inputType:'BLOB',inputID:'log-input',sourceRef:artifactRef,slotID:'log',sha256:sha(input)}],
      methodSpec:{mode:'TOOL',name:'auth-count-v1',version:VALUE('1.0'),executableDigest:VALUE(sha(tool))},
      parameters:VALUE(runner.PARAMETERS),environment:VALUE(plan.environment),
      outputs:[{slotID:'parsed',sha256:sha(expectedBytes),byteLength:expectedBytes.length,mediaType:'application/json'}],
      gaps:version===1?['Synthetic protocol fixture']:['Controlled false-output-at-registration test condition']},[artifactRef],version,previous.exam);
    const examRef=m.materialRef(exam);
    const analysis=material(fi,'analysis','PROCESS',{phase:'ANALYSIS',
      inputBindings:[{inputType:'BLOB',inputID:'parsed-input',sourceRef:examRef,slotID:'parsed',sha256:sha(expectedBytes)}],
      methodSpec:{mode:'MANUAL',name:'Declared output interpretation',rationale:'Interpret counts without inferring authorization or chronology'},
      parameters:NA('Manual interpretation'),environment:UNKNOWN('Analyst environment not captured'),outputs:[],
      gaps:['Counts alone do not establish authorization or chronology'],
      resultSummary:`The declared output reports ${version===1?1:99} denied and 1 successful result(s); no unauthorized-access conclusion is established.`},[examRef],version,previous.analysis);
    const finding=material(fi,'finding','FINDING',{statement:analysis.body.data.resultSummary,claimType:'INTERPRETATION',
      rationale:'Based on the explicitly referenced analysis',assumptions:['Declared process outputs require independent checking'],
      interpretationLimits:['Synthetic fixture; no real compromise is established'],supportRefs:[m.materialRef(analysis)],supportStatus:'SUPPORT_DECLARED'},[m.materialRef(analysis)],version,previous.finding);
    const reportPath=path.join(vdir,'report.md');keepBytes(reportPath,Buffer.from(`# Controlled LWFA report v${version}\n\n## Finding\n${finding.body.data.statement}\n\nSynthetic protocol fixture, not a real forensic conclusion.\n`));
    const reportBytes=fileBytes(reportPath);
    const report=material(fi,'report','REPORT',{documentDescriptor:{slotID:'report',sha256:sha(reportBytes),byteLength:reportBytes.length,mediaType:'text/markdown'},
      claims:[{claimID:'authentication-counts',statement:finding.body.data.statement,findingRefs:[m.materialRef(finding)],documentLocator:'Finding'}]},[m.materialRef(finding)],version,previous.report);
    if(version===1)reportV1=report;
    const basis=once(path.join(vdir,'basis.json'),()=>ar.checkpoint());
    const request=submit(ar,'OpenReview',`request-v${version}`,'review',{targetRef:m.materialRef(report),reviewerActorRef:ir.actor,
      scope:{purpose:'Independent reconstruction and controlled rerun of the selected report basis',extraRoots:[]},checkpointBasis:basis,
      policyRef:profiles.policy.ref,verifierSpecRef:profiles.verifier.ref,checkPlan:[{checkID:'rerun-examination',checkType:'RERUN_PROCESS',
        processRef:examRef,inputBindings:exam.body.data.inputBindings,expectedOutputs:exam.body.data.outputs,
        comparator:'JSON_CANONICAL_EQUAL',requiredEnvironment:exam.body.data.environment}],predecessorRequestRef:null});
    // Exporter reads current committed envelopes through its own identity.
    const producerRecords=[incident,artifact,exam,analysis,finding,report].map(e=>fi.record(caseID,e.recordID));
    const files=new Map([[pkg.blobKey({ownerVersionRef:artifactRef,slotID:'log'}),inputPath],
      [pkg.blobKey({ownerVersionRef:examRef,slotID:'parsed'}),expectedPath],
      [pkg.blobKey({ownerVersionRef:m.materialRef(report),slotID:'report'}),reportPath]]);
    const packageDir=path.join(vdir,'package');
    if(!fs.existsSync(path.join(packageDir,'manifest.json')))pkg.buildPackage(packageDir,request,caseConfig,
      pkg.closure(new Map(producerRecords.map(e=>[e.recordID,e])),request.body),files,new Map([[pkg.rkey(examRef),runner.TOOL]]));
    const packageRecord=submit(fi,'RegisterPackage',`package-v${version}`,'package',{requestRef:m.recordRef(request),
      manifestHash:sha(fileBytes(path.join(packageDir,'manifest.json'),1024*1024)),formatVersion:'LWFA_PACKAGE_2',
      declaredExporter:VALUE('LWFA controlled exporter 0.4.0')});
    // Reviewer never uses producer-side confirmed JSON as the ledger authority.
    const ownRequest=ir.record(caseID,request.recordID),ownPackage=ir.record(caseID,packageRecord.recordID);
    ensure(same(ownRequest.body.reviewerActorRef,ir.actor),'INDEPENDENT_REVIEWER_ASSIGNMENT');
    const history=once(path.join(vdir,'history.json'),()=>ir.checkpoint());
    const snapshot=ir.snapshot(caseID,history,path.join(vdir,'org3-history'));
    const checked=pkg.verifyPackage(packageDir,ownRequest,ownPackage,snapshot,history);
    const c=ownRequest.body.checkPlan[0],proc=checked.materials.find(e=>same(m.materialRef(e),c.processRef));
    let result;
    const existingPayload=path.join(outbox,`observation-v${version}.payload.json`);
    if(fs.existsSync(existingPayload)) result=readJson(existingPayload).observation.checkResults[0];
    else {
      const inputRef={ownerVersionRef:c.inputBindings[0].sourceRef,slotID:c.inputBindings[0].slotID};
      result=runner.rerun(proc,c,checked.blobBytes.get(pkg.blobKey(inputRef)),
        checked.blobBytes.get(pkg.blobKey({ownerVersionRef:c.processRef,slotID:'parsed'})),
        checked.toolBytes.get(pkg.rkey(c.processRef)),path.join(vdir,'reviewer-execution'));
    }
    const targetStatus=version===1?'EXECUTED_MATCH':'EXECUTED_MISMATCH';ensure(result.status===targetStatus,`RERUN_EXPECTATION_FAILED: ${result.status}: ${result.reason}`);
    const body={intendedRequestRef:m.recordRef(ownRequest),attemptID:`attempt-v${version}`,mode:'CHECKS',checkpointHistory:history,
      limitations:['Logical organizations on one host; no physical institutional independence',
        'Peer validation metadata is trusted over authenticated TLS; signatures and consensus are not independently revalidated',
        'Execution evidence is an attributed reviewer record, not cryptographic proof of execution or substantive truth',
        'M2-only regression subcase; issue handling tested by the separate M3 workflow'],
      packageRef:m.recordRef(ownPackage),manifestHash:ownPackage.body.manifestHash,binding:checked.binding,context:checked.context,
      materialResults:checked.materialResults,checkResults:[result]};
    const observation=submit(ir,'AppendObservation',`observation-v${version}`,'observation',body);
    ensure(observation.body.checkResults[0].status===targetStatus && same(observation.actor,ir.actor),'OBSERVATION_QUERY_MISMATCH');
    writeJson(path.join(vdir,'verification-summary.json'),{target:m.materialRef(report),binding:checked.binding,context:checked.context,
      contextMeaning:checked.contextMeaning,materialResults:checked.materialResults,history:checked.history,procedure:result.status,
      observationRef:m.recordRef(observation),trustModel:'TRUSTED_ORG3_PEER_VALIDATION_METADATA'});
    outcomes.push({version,procedure:result.status,recordID:observation.recordID});
    // Deliberately invalid proposals are evaluated without broadcasting.
    const base={schemaVersion:'1.0',caseID,operationID:`negative-v${version}`,recordID:`negative-v${version}`,observation:body};
    const controls=[['wrong-reviewer',fi,p=>p,'UNAUTHORIZED'],
      ['missing-execution',ir,p=>{delete p.observation.checkResults[0].execution;return p;},'SCHEMA_ERROR'],
      ['wrong-tool',ir,p=>{p.observation.checkResults[0].execution.toolDigest='0'.repeat(64);return p;},'CHECK_PLAN_MISMATCH'],
      ['foreign-check',ir,p=>{p.observation.checkResults[0].checkID='foreign-check';return p;},'CHECK_PLAN_MISMATCH'],
      ['duplicate-attempt',ir,p=>p,'DUPLICATE_ATTEMPT']];
    const headBefore=ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50});
    for(const [name,client,mutate,expectedCode] of controls) {
      const p=m.parseJson(m.canonicalJson(base));p.operationID+=`-${name}`;p.recordID+=`-${name}`;
      if(name!=='duplicate-attempt')p.observation.attemptID+=`-${name}`;
      let rejected=false;try {client.query('AppendObservation',mutate(p));}catch(e) {rejected=e.fabricFailure && e.message.includes(expectedCode);if(!rejected)throw e;}
      ensure(rejected,`NEGATIVE_PROPOSAL_UNEXPECTED_ACCEPTANCE: ${name}`);
      negatives.push({version,name,expectedCode,result:'EXPECTED_PROPOSAL_REJECTION'});
    }
    ensure(same(headBefore,ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50})),'NEGATIVE_QUERY_CHANGED_STATE');
    Object.assign(previous,{exam,analysis,finding,report});
  }
  const retained=ir.query('GetMaterialVersion',{caseID,objectID:'report',version:1});
  ensure(same(retained,reportV1),'OLD_REPORT_CHANGED_AFTER_REVISION');
  const oldAfter=baseline.query('ListCaseJournal',{caseID:'LWFA-SMOKE-001',afterSequence:0,limit:50});
  ensure(same(oldAfter,oldBefore),'V031_BASELINE_CHANGED');
  const journal=ir.query('ListCaseJournal',{caseID,afterSequence:0,limit:50});
  ensure(journal.headSequence===17 && journal.items.length===17 && !journal.hasMore,'UNEXPECTED_FINAL_JOURNAL');
  const summary={release:'0.5.1',caseID,chaincode:ir.name,headSequence:journal.headSequence,outcomes,negativeProposals:negatives,
    oldReportBinding:'PRESERVED',v031Journal:'UNCHANGED',trustModel:'TLS_AUTHENTICATED_ORG3_PEER_WITH_VALIDATION_METADATA',
    scope:'ONE_SYNTHETIC_SCENARIO_TWO_CONTROLLED_VERSIONS',result:'PASS'};
  writeJson(path.join(WORK,'summary.json'),summary);writeJson(path.join(WORK,'journal.json'),journal);
  console.log(JSON.stringify(summary,null,2));console.log('PASS: controlled rerun smoke, not final research evaluation');
}
if(require.main===module)main().catch(e=>{console.error(e.stack);process.exitCode=1;});
module.exports={main,normalise};
