'use strict';
const {spawnSync}=require('node:child_process');
const os=require('node:os'); const crypto=require('node:crypto');
const {fs,path,m,ensure,sha,same,fileBytes,utf8,writeJson}=require('./io');
const TOOL=path.join(__dirname,'../tools/auth-count.js');
const PARAMETERS=Object.freeze({adapter:'auth-count-v1',argv:['/work/input.log'],outputSlot:'parsed'});
const PERSISTENCE_TOOL=path.join(__dirname,'../tools/persistence-lines.js');
const PERSISTENCE_PARAMETERS=Object.freeze({adapter:'persistence-lines-v1',argv:['/work/input.log'],outputSlot:'parsed'});
function adapterFor(parameters){
  if(same(parameters,PARAMETERS))return {tool:TOOL};
  if(same(parameters,PERSISTENCE_PARAMETERS))return {tool:PERSISTENCE_TOOL};
  throw Error('PARAMETERS_UNSUPPORTED');
}
function approvedTool(bytes){return [TOOL,PERSISTENCE_TOOL].some(p=>sha(bytes)===sha(fileBytes(p)));}
function canonicalDigest(bytes) {return sha(Buffer.from(m.canonicalJson(m.parseJson(utf8(bytes)))));}
function compareJson(expected,actual,slotID='parsed') {
  const a=canonicalDigest(expected),b=canonicalDigest(actual);
  return {slotID,expectedCanonicalSha256:a,actualCanonicalSha256:b,equal:a===b};
}
function checked(cmd,args,options={}) {
  const r=spawnSync(cmd,args,{timeout:60000,maxBuffer:2*1024*1024,...options});
  ensure(!r.error && r.status===0,`${cmd} failed: ${r.error?.message || r.stderr?.toString()}`);return r.stdout;
}
function environment(image='hyperledger/fabric-nodeenv:2.5') {
  const info=JSON.parse(checked('docker',['image','inspect',image]).toString())[0];
  ensure(/^sha256:[0-9a-f]{64}$/.test(info.Id),'IMAGE_ID_REQUIRED');
  ensure(info.Os==='linux','LINUX_IMAGE_REQUIRED');
  const node=checked('docker',['run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
    '--entrypoint','/usr/local/bin/node',info.Id,'--version']).toString().trim();
  ensure(/^v22\./.test(node),'NODE22_IMAGE_REQUIRED');
  return {imageID:info.Id,platform:`${info.Os}/${info.Architecture}`,nodeVersion:node,
    entrypoint:'/usr/local/bin/node',locale:'C',timezone:'UTC',network:'none',readOnlyRoot:true,
    memoryMiB:256,pidsLimit:64,cpus:1,timeoutMs:15000,maxOutputBytes:1048576};
}
function dockerArgs(env,dir,name) {
  return ['run','--rm','--name',name,'--pull','never','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--user','65534:65534','--memory','256m','--memory-swap','256m',
    '--pids-limit','64','--cpus','1','--ulimit','nofile=128:128','--env','LC_ALL=C','--env','TZ=UTC',
    '--mount',`type=bind,source=${dir},target=/work,readonly`,
    '--entrypoint',env.entrypoint,env.imageID,'/work/tool.js','/work/input.log'];
}
function execute(env,input,tool,work) {
  ensure(same(env,environment(env.imageID)),'ACTUAL_ENVIRONMENT_MISMATCH');
  ensure(approvedTool(tool),'UNTRUSTED_TOOL');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'lwfa-run-'));
  fs.chmodSync(dir,0o755);fs.writeFileSync(path.join(dir,'input.log'),input,{mode:0o444});
  fs.writeFileSync(path.join(dir,'tool.js'),tool,{mode:0o444});
  const name=`lwfa-rerun-${crypto.randomBytes(8).toString('hex')}`;
  const startedAt=new Date().toISOString(); let result;
  try {
    result=spawnSync('docker',dockerArgs(env,dir,name),{timeout:env.timeoutMs,killSignal:'SIGKILL',maxBuffer:env.maxOutputBytes});
  } finally {
    // Name-based cleanup removes containers left running after Docker CLI termination.
    spawnSync('docker',['rm','-f',name],{timeout:15000,stdio:'ignore'});
    fs.rmSync(dir,{recursive:true,force:true});
  }
  const finishedAt=new Date().toISOString();
  const stdout=Buffer.from(result.stdout||''),stderr=Buffer.from(result.stderr||'');
  fs.mkdirSync(work,{recursive:true});fs.writeFileSync(path.join(work,'actual-output.json'),stdout);
  fs.writeFileSync(path.join(work,'stderr.log'),stderr);
  return {stdout,stderr,startedAt,finishedAt,exitCode:result.status,signal:result.signal||null,
    errorCode:result.error?.code==='ETIMEDOUT'?'TIMEOUT':result.error?'RUNNER_ERROR':result.status!==0?'NONZERO_EXIT':null};
}
function rerun(process,check,input,expected,tool,work,exec=execute) {
  const data=process.body.data;
  try {
    ensure(data.methodSpec.mode==='TOOL' && data.methodSpec.executableDigest.status==='VALUE','TOOL_UNAVAILABLE');
    ensure(check.comparator==='JSON_CANONICAL_EQUAL','COMPARATOR_UNSUPPORTED');
    ensure(data.inputBindings.length===1 && data.inputBindings[0].inputType==='BLOB' && data.outputs.length===1,'ADAPTER_SHAPE_UNSUPPORTED');
    ensure(data.parameters.status==='VALUE','PARAMETERS_UNSUPPORTED');
    const adapter=adapterFor(data.parameters.value);
    ensure(data.environment.status==='VALUE','ENVIRONMENT_NOT_DECLARED');
    ensure(same(check.inputBindings,data.inputBindings) && same(check.expectedOutputs,data.outputs) &&
      same(check.requiredEnvironment,data.environment) && same(check.processRef,m.materialRef(process)),'CHECK_BASIS_MISMATCH');
    ensure(sha(input)===data.inputBindings[0].sha256,'INPUT_HASH_MISMATCH');
    ensure(sha(tool)===data.methodSpec.executableDigest.value && sha(tool)===sha(fileBytes(adapter.tool)),'TOOL_HASH_MISMATCH');
    const desc=data.outputs[0];ensure(desc.slotID==='parsed' && desc.mediaType==='application/json','OUTPUT_ADAPTER_UNSUPPORTED');
    ensure(sha(expected)===desc.sha256 && expected.length===desc.byteLength,'EXPECTED_OUTPUT_HASH_MISMATCH');
    canonicalDigest(expected);
  } catch(error) { return {checkID:check.checkID,status:'NOT_RUN',reason:error.message}; }
  let run;
  try {run=exec(data.environment.value,input,tool,work);}
  catch(error) {return {checkID:check.checkID,status:'NOT_RUN',reason:`PRE_EXECUTION: ${error.message}`};}
  const execution={processRef:m.materialRef(process),toolDigest:sha(tool),inputBindings:data.inputBindings,
    parameters:data.parameters,environment:data.environment,expectedOutputs:data.outputs,actualOutputs:[],comparisons:[],
    comparator:check.comparator,comparatorVersion:'1',
    runner:{name:'lwfa-docker-runner',version:'0.4.0',sha256:sha(fs.readFileSync(__filename))},
    startedAt:run.startedAt,finishedAt:run.finishedAt,exitCode:run.exitCode,signal:run.signal,errorCode:run.errorCode,
    stdoutSha256:sha(run.stdout),stderrSha256:sha(run.stderr)};
  let status='EXECUTION_ERROR',reason=run.errorCode||'';
  if(!run.errorCode) {
    execution.actualOutputs=[{slotID:'parsed',sha256:sha(run.stdout),byteLength:run.stdout.length,mediaType:'application/json'}];
    try {
      const comparison=compareJson(expected,run.stdout); execution.comparisons=[comparison];
      status=comparison.equal?'EXECUTED_MATCH':'EXECUTED_MISMATCH'; reason='JSON_CANONICAL_EQUAL comparison over recomputed outputs';
    } catch(error) {execution.errorCode='INVALID_OUTPUT_JSON';reason=`Output parsing failed: ${error.message}`;}
  }
  const result={checkID:check.checkID,status,reason,execution};
  m.validateExecution(execution,status,process.caseID);m.bindExecution(execution,check,data,process.caseID);
  writeJson(path.join(work,'execution-result.json'),result);
  return result;
}
module.exports={TOOL,PARAMETERS,PERSISTENCE_TOOL,PERSISTENCE_PARAMETERS,adapterFor,approvedTool,environment,dockerArgs,execute,canonicalDigest,compareJson,rerun};
