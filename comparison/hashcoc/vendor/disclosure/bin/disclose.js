#!/usr/bin/env node
'use strict';
// Offline application assurance over trusted-peer block files. The required cutoff
// comes from the reviewer, never from the last file supplied by the package author.
const fs=require('node:fs'),path=require('node:path');
const core=require('../lib/core'),Hist=core.req('client/history'),{m,utf8}=core.req('client/io');
const C=require('../lib/creators'),{checkpointPart,validateCheckpoint,validateSummary}=require('../lib/checkpoint');
const {assessResearchPackage}=require('../lib/assurance');
const deployment=core.req('chaincode/profiles.json').deployment;
function args(argv){
 const out={namespace:'lwfaContractV051'};
 const names=new Set(['snapshot-dir','expected-checkpoint','case','request','namespace','channel','out','package-dir','package-record','presented-disclosure']);
 for(let i=0;i<argv.length;i+=2){
  const name=argv[i]?.replace(/^--/,'');
  if(!argv[i]?.startsWith('--')||!names.has(name)||!argv[i+1]||argv[i+1].startsWith('--'))throw new Error(`INVALID_ARGUMENT:${argv[i]}`);
  const key=name.replace(/-([a-z])/g,(_,c)=>c.toUpperCase());
  if(Object.hasOwn(out,key)&&key!=='namespace')throw new Error(`DUPLICATE_ARGUMENT:${name}`);
  out[key]=argv[i+1];
 }
 for(const k of ['snapshotDir','expectedCheckpoint','case','request'])if(!out[k])throw new Error(`MISSING_ARGUMENT:${k}`);
 if(Boolean(out.packageDir)!==Boolean(out.packageRecord))throw new Error('PACKAGE_DIR_AND_RECORD_REQUIRED_TOGETHER');
 m.assertID(out.case,'caseID');m.assertID(out.request,'recordID');
 return out;
}
function readJSON(file){
 const stat=fs.statSync(file);if(!stat.isFile()||stat.size>1024*1024)throw new Error('INPUT_JSON_SIZE_OR_TYPE');
 return m.parseJson(utf8(fs.readFileSync(file)));
}
function main(){
 if(process.argv.length===3 && ['--help','-h'].includes(process.argv[2])){
  process.stdout.write('Usage: node bin/disclose.js --snapshot-dir DIR --expected-checkpoint JSON --case CASE_ID --request REQUEST_RECORD_ID [--namespace lwfaContractV051] [--channel forensic-channel] [--out JSON]\n'+
   'Optional package assessment: --package-dir DIR --package-record RECORD_ID\n'+
   'Optional presented disclosure check: --presented-disclosure JSON\n'+
   'Expected checkpoint JSON: channelID, blockNumber (string), blockHeaderHash, provenance:{source:"REVIEWER_SUPPLIED",reference:"independent anchor reference"}.\n'+
   'Snapshot-only mode does not verify package bytes. Exit 0 means assessment completed, not assurance satisfied.\n');return;
 }
 const a=args(process.argv.slice(2)),expected=readJSON(a.expectedCheckpoint),cp=checkpointPart(expected);
 const channel=a.channel||cp.channelID,end=BigInt(cp.blockNumber);
 if(end>=4096n)throw new Error('REPLAY_BLOCK_LIMIT_4096');
 const files=fs.readdirSync(a.snapshotDir).filter(f=>/^block-\d+\.pb$/.test(f)).sort((x,y)=>Number(x.match(/\d+/)[0])-Number(y.match(/\d+/)[0]));
 if(files.length!==Number(end)+1)throw new Error('EXPECTED_CHECKPOINT_BLOCK_RANGE_MISMATCH');
 files.forEach((f,i)=>{if(f!==`block-${i}.pb`)throw new Error(`BLOCK_SEQUENCE_GAP:${f}`);});
 let total=0;
 const blocks=files.map(f=>{
  const file=path.join(a.snapshotDir,f),stat=fs.statSync(file);total+=stat.size;
  if(!stat.isFile()||stat.size>32*1024*1024||total>512*1024*1024)throw new Error('SNAPSHOT_BYTE_LIMIT');
  return fs.readFileSync(file);
 });
 const snapshot=Hist.replay(blocks,channel,a.namespace,a.case);
 validateCheckpoint(snapshot,expected,channel);
 const summaryPath=path.join(a.snapshotDir,'summary.json');
 if(fs.existsSync(summaryPath))validateSummary(readJSON(summaryPath),expected);
 const request=snapshot.records.get(a.request);
 if(!request||request.kind!=='REVIEW_REQUEST')throw new Error('REQUEST_NOT_IN_SNAPSHOT');
 const identities=C.shimAvailable()?C.identities(blocks,channel,deployment.roleAttribute):null;
 const packageRecord=a.packageRecord?snapshot.records.get(a.packageRecord):undefined;
 if(a.packageRecord&&(!packageRecord||packageRecord.kind!=='PACKAGE_RECORD'))throw new Error('PACKAGE_RECORD_NOT_IN_SNAPSHOT');
 const result=assessResearchPackage({snapshot,request,historyCheckpoint:cp,identities,expectedCheckpoint:expected,
  actualChannel:channel,packageDir:a.packageDir,packageRecord,
  presentedDisclosure:a.presentedDisclosure?readJSON(a.presentedDisclosure):undefined});
 const text=m.canonicalJson(result);
 if(a.out)fs.writeFileSync(a.out,text+'\n');else process.stdout.write(text+'\n');
 process.stderr.write(`disclosure flags: ${(result.disclosure?.flags||[]).join(', ')||'(none)'}\n`);
}
try{main();}catch(error){process.stderr.write(`ERROR ${error.message}\n`);process.exitCode=1;}
