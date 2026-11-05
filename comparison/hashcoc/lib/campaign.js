'use strict';
const {io,H,C,CP}=require('./core');
const {fs,path,readJson,sha,same,m}=io;
function inventory(root) {
  const rows=[];
  function walk(dir) {
    for(const name of fs.readdirSync(dir).sort()) {
      const f=path.join(dir,name),s=fs.lstatSync(f);
      if(s.isSymbolicLink())throw new Error('INPUT_SYMLINK_REJECTED: '+f);
      if(s.isDirectory())walk(f);
      else if(s.isFile())rows.push({path:path.relative(root,f).split(path.sep).join('/'),bytes:s.size,sha256:sha(fs.readFileSync(f))});
      else throw new Error('INPUT_NOT_REGULAR: '+f);
    }
  }
  // Inventory is not a protocol envelope; deterministic sorted JSON may exceed
  // the core protocol's per-record canonical JSON size cap.
  walk(root);return {digestEncoding:'SHA256_UTF8_JSON_STRINGIFY_SORTED_FILE_ROWS',sha256:sha(Buffer.from(JSON.stringify(rows))),files:rows};
}
function within(root,relative) {
  if(typeof relative!=='string'||path.isAbsolute(relative))throw new Error('RELATIVE_INPUT_PATH_REQUIRED');
  const out=path.resolve(root,relative),rel=path.relative(root,out);
  if(rel==='..'||rel.startsWith('..'+path.sep))throw new Error('INPUT_PATH_ESCAPE');
  return out;
}
function createLoader(campaign) {
  campaign=path.resolve(campaign);
  if(!C.shimAvailable())throw new Error('FABRIC_SHIM_UNAVAILABLE: run npm run setup');
  const network=readJson(path.join(campaign,'network-binding.json'));
  const namespace=network.receipt?.chaincode,channel=network.receipt?.channel;
  if(!namespace||!channel)throw new Error('CAPTURE_NETWORK_BINDING_REQUIRED');
  const cache=new Map();
  function load(row) {
    const caseDir=within(campaign,'cases/'+row.family),request=readJson(within(caseDir,row.request));
    const snapshotDir=within(caseDir,row.snapshot),key=snapshotDir+'|'+request.caseID;
    if(!cache.has(key)) {
      const expectedCheckpoint=readJson(path.join(snapshotDir,'expected-checkpoint.json'));
      const end=BigInt(expectedCheckpoint.blockNumber);
      if(end<0n||end>=4096n)throw new Error('REPLAY_BLOCK_LIMIT_4096');
      const files=fs.readdirSync(snapshotDir).filter(f=>/^block-\d+\.pb$/.test(f));
      if(files.length!==Number(end)+1)throw new Error('SNAPSHOT_BLOCK_COUNT_MISMATCH');
      const blocks=Array.from({length:Number(end)+1},(_,i)=>fs.readFileSync(path.join(snapshotDir,'block-'+i+'.pb')));
      const snapshot=H.replay(blocks,channel,namespace,request.caseID);
      CP.validateCheckpoint(snapshot,expectedCheckpoint,channel);
      const identities=C.identities(blocks,channel,'lwfa.role');
      const summary=readJson(path.join(snapshotDir,'summary.json'));
      CP.validateSummary(summary,expectedCheckpoint);
      // The capture is historical; this process makes no new authenticated peer connection.
      const acquisition=readJson(path.join(snapshotDir,'acquisition.json'));
      if(acquisition.mode!=='TLS_AUTHENTICATED_ORG3_PEER'||acquisition.reader?.mspID!=='Org3MSP'||
        !same(acquisition.checkpoint,CP.checkpointPart(expectedCheckpoint)))throw new Error('CAPTURE_ACQUISITION_BINDING_MISMATCH');
      cache.set(key,{snapshot,identities,expectedCheckpoint,actualChannel:channel,acquisition});
    }
    const common=cache.get(key);
    return {...common,request,packageRecord:readJson(within(caseDir,row.packageRecord)),packageDir:within(caseDir,row.packageDir),
      ...(row.presentedDisclosure?{presentedDisclosure:readJson(within(caseDir,row.presentedDisclosure))}:{}),
      storedAssessment:readJson(within(caseDir,row.assessment))};
  }
  return {load,namespace,channel};
}
function trialInputs(row,lock) {
  const base='cases/'+row.family+'/',exact=new Set([row.request,row.packageRecord,...(row.presentedDisclosure?[row.presentedDisclosure]:[])].map(p=>base+p));
  // Stored assessment is deliberately NOT an input to either checker.
  const files=lock.files.filter(f=>f.path==='network-binding.json'||exact.has(f.path)||f.path.startsWith(base+row.snapshot+'/')||f.path.startsWith(base+row.packageDir+'/'));
  return {sha256:sha(Buffer.from(JSON.stringify(files))),files};
}
module.exports={inventory,within,createLoader,trialInputs};
