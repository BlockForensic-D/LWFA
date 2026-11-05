#!/usr/bin/env node
'use strict';
const {ROOT,io,A}=require('../lib/core');
const {fs,path,sha,same,m,readJson}=io;
const {assessHashCoC}=require('../lib/baseline');
const {inventory,createLoader,trialInputs}=require('../lib/campaign');
function save(f,value) {fs.writeFileSync(f,JSON.stringify(value,null,2)+'\n');}
function args(argv) {
  const out={};for(let i=0;i<argv.length;i+=2){if(!['--campaign','--out','--plan'].includes(argv[i])||!argv[i+1])throw new Error('Usage: node bin/compare.js --campaign /path/to/campaign --out /new/output-dir [--plan /plan.json]');out[argv[i].slice(2)]=argv[i+1];}
  if(!out.campaign||!out.out)throw new Error('Both --campaign and --out are required');return out;
}
function diffPaths(a,b,p='') {
  if(a===undefined||b===undefined)return a===b?[]:[p];
  if(same(a,b))return [];
  if(a&&b&&typeof a==='object'&&typeof b==='object')return [...new Set([...Object.keys(a),...Object.keys(b)])].flatMap(k=>diffPaths(a[k],b[k],p+'/'+k));
  return [p];
}
function main() {
  const arg=args(process.argv.slice(2)),campaign=fs.realpathSync(arg.campaign),out=path.resolve(arg.out);
  if(out===campaign||out.startsWith(campaign+path.sep)||campaign.startsWith(out+path.sep))throw new Error('OUTPUT_MUST_BE_OUTSIDE_CAMPAIGN');
  if(fs.existsSync(out))throw new Error('OUTPUT_ALREADY_EXISTS: choose a new directory');
  const planPath=path.resolve(arg.plan||path.join(ROOT,'comparison-plan.json')),plan=readJson(planPath);
  const origin=readJson(path.join(ROOT,'source-origin.json'));
  for(const f of origin.files)if(sha(fs.readFileSync(path.join(ROOT,f.path)))!==f.sha256)throw new Error('VENDORED_SOURCE_CHANGED: '+f.path);
  const implementationFiles=['package.json','baseline-spec.json','source-origin.json',...['bin','lib'].flatMap(dir=>fs.readdirSync(path.join(ROOT,dir)).filter(f=>f.endsWith('.js')).sort().map(f=>dir+'/'+f))];
  const implementation=implementationFiles.map(p=>({path:p,sha256:sha(fs.readFileSync(path.join(ROOT,p)))}));
  const lock=inventory(campaign),loader=createLoader(campaign),results=[];
  fs.mkdirSync(out,{recursive:true});fs.mkdirSync(path.join(out,'trials'));
  save(path.join(out,'input-lock.json'),lock);fs.copyFileSync(planPath,path.join(out,'comparison-plan.json'));
  save(path.join(out,'implementation-lock.json'),implementation);
  for(const row of plan.rows) {
    if(!/^[A-Za-z0-9_-]+$/.test(row.id))throw new Error('UNSAFE_TRIAL_ID');
    const inputs=trialInputs(row,lock);
    const result={id:row.id,family:row.family,dimension:row.dimension,pairedInputSHA256:inputs.sha256,baselineInputSHA256:inputs.sha256,pccInputSHA256:inputs.sha256};
    try {
      const options=loader.load(row);
      result.baseline=assessHashCoC(options);
      result.pcc=A.assessResearchPackage(options);
      result.archivedPccAgreement={status:same(result.pcc,options.storedAssessment)?'EXACT_CANONICAL_MATCH':'MISMATCH',
        differingPaths:diffPaths(result.pcc,options.storedAssessment)};
      result.execution='COMPLETED';
    }catch(e){result.execution='ERROR';result.error={name:e.name,message:e.message};}
    results.push(result);save(path.join(out,'trials',row.id+'.json'),result);
    process.stdout.write(row.id+' '+result.execution+' '+(result.archivedPccAgreement?.status||result.error?.message)+'\n');
  }
  const after=inventory(campaign),unchanged=lock.sha256===after.sha256&&lock.files.length===after.files.length;
  const summary={format:'LWFA_HASH_COC_COMPARISON_1',studyType:plan.studyType,createdAt:new Date().toISOString(),
    runtime:{node:process.version,platform:process.platform,arch:process.arch,fabricShim:require('node:module').createRequire(path.join(ROOT,'vendor/disclosure/package.json'))('fabric-shim/package.json').version},
    implementationSHA256:sha(Buffer.from(JSON.stringify(implementation))),vendorIntegrity:'ALL_PINNED_FILES_MATCH',
    planSHA256:sha(fs.readFileSync(planPath)),sourceCampaignSHA256:lock.sha256,sourceFiles:lock.files.length,
    sourceCampaignUnchanged:unchanged,trialCount:results.length,familyCount:new Set(results.map(x=>x.family)).size,
    completed:results.filter(x=>x.execution==='COMPLETED').length,errors:results.filter(x=>x.execution==='ERROR').map(x=>x.id),
    archivedPccExactMatches:results.filter(x=>x.archivedPccAgreement?.status==='EXACT_CANONICAL_MATCH').length,
    archivedPccMismatches:results.filter(x=>x.archivedPccAgreement?.status==='MISMATCH').map(x=>x.id),
    liveFabricRun:false,forensicProceduresRerun:false,independentOracleApproval:false,
    interpretation:'Retrospective dimension-wise comparison on one existing bounded SecRespond case with related authored scenario variants. NOT_EVALUATED is neither acceptance nor failure; no detection accuracy or performance claim.',
    trust:'Captured reviewer checkpoint and original Org3 peer validation metadata remain trusted. Raw block hashes, order, record commitments and actor bindings are rechecked offline. No fresh peer connection or independent MSP/signature/consensus verification.'};
  save(path.join(out,'results.json'),{summary,results});save(path.join(out,'summary.json'),summary);
  const cols=['id','family','dimension','execution','baseline_binding','baseline_blob_statuses','baseline_creator','baseline_context','baseline_history','pcc_binding','pcc_context','pcc_blob_statuses','pcc_flags','pcc_presented_coverage','pcc_missing_record_ids','archived_pcc_agreement','paired_input_sha256'];
  const status=rows=>rows?.length?rows.map(x=>x.status).join('|'):'NOT_ASSESSED';
  const quote=v=>'"'+String(v??'').replaceAll('"','""')+'"';
  const csv=results.map(r=>{const b=r.baseline,p=r.pcc,pa=p?.packageAssessment,pc=p?.presentedDisclosureCheck;return [r.id,r.family,r.dimension,r.execution,b?.binding,status(b?.materialResults),b?.creatorBinding,b?.obligations.basisContextCompleteness,b?.obligations.presentedHistoryCompleteness,pa?.binding,pa?.context,status(pa?.materialResults),p?.disclosure.flags.join('|'),pc?.coverageStatus||pc?.status,[...(pa?.contextFailure?.missing||[]),...(pc?.missingRecordIDs||[])].join('|'),r.archivedPccAgreement?.status,r.pairedInputSHA256];});
  fs.writeFileSync(path.join(out,'comparison.csv'),[cols,...csv].map(row=>row.map(quote).join(',')).join('\n')+'\n');
  process.stdout.write(JSON.stringify(summary,null,2)+'\n');
  if(!unchanged||summary.errors.length||summary.archivedPccMismatches.length)process.exitCode=1;
}
try{main();}catch(e){process.stderr.write(e.stack+'\n');process.exitCode=1;}
