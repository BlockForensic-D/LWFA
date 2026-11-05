'use strict';
const {spawnSync}=require('node:child_process');
const {createRequire}=require('node:module'); const os=require('node:os');
const {fs,path,m,ensure,readJson,writeJson,same,utf8}=require('./io');
const issues=require('../chaincode/issues');
const h=require('./history'); const state=require('../chaincode/state');
const loadSDK=createRequire(path.resolve(__dirname,'../chaincode/package.json'));
const CONFIG={
  AcquisitionOperator:{org:1,port:7051},ForensicInvestigator:{org:1,port:7051},
  AssuranceReviewer:{org:2,port:9051},IndependentReviewer:{org:3,port:11051}
};
class FabricClient {
  constructor(role,options={}) {
    ensure(CONFIG[role],'UNKNOWN_ROLE');this.role=role;this.org=CONFIG[role].org;
    this.fabric=options.fabric||process.env.LWFA_FABRIC_ROOT||path.join(os.homedir(),'2labforensic/fabric-samples');
    this.tn=path.join(this.fabric,'test-network');this.channel=options.channel||'forensic-channel';
    this.name=options.name||'lwfaContractV051';this.peer=path.join(this.fabric,'bin/peer');
    this.endpoint=`localhost:${CONFIG[role].port}`;
    const domain=`org${this.org}.example.com`;
    const msp=path.join(this.tn,'organizations/peerOrganizations',domain,'users',`${role}@${domain}`,'msp');
    const tls=this.tls(this.org);
    this.env={...process.env,PATH:`${this.fabric}/bin:${process.env.PATH}`,FABRIC_CFG_PATH:path.join(this.fabric,'config'),
      CORE_PEER_TLS_ENABLED:'true',CORE_PEER_LOCALMSPID:`Org${this.org}MSP`,CORE_PEER_ADDRESS:this.endpoint,
      CORE_PEER_TLS_ROOTCERT_FILE:tls,CORE_PEER_MSPCONFIGPATH:msp,FABRIC_LOGGING_SPEC:'error'};
    const certs=fs.readdirSync(path.join(msp,'signcerts')).filter(v=>fs.statSync(path.join(msp,'signcerts',v)).isFile());
    ensure(certs.length===1,'ONE_SIGNING_CERT_REQUIRED');
    const {ClientIdentity}=loadSDK('fabric-shim');
    const cid=new ClientIdentity({getChannelID:()=>this.channel,getTxID:()=> 'identity-preflight',
      getCreator:()=>({mspid:`Org${this.org}MSP`,idBytes:fs.readFileSync(path.join(msp,'signcerts',certs[0]))})});
    this.identity=state.authenticate({clientIdentity:cid},require('../chaincode/profiles.json').deployment);
    ensure(this.identity.role===role,'ROLE_ATTRIBUTE_MISMATCH');this.actor=this.identity.actor;
  }
  tls(org) {return path.join(this.tn,`organizations/peerOrganizations/org${org}.example.com/peers/peer0.org${org}.example.com/tls/ca.crt`);}
  call(args,log) {
    const result=spawnSync(this.peer,args,{cwd:this.tn,env:this.env,timeout:120000,maxBuffer:96*1024*1024});
    if(log) {fs.mkdirSync(path.dirname(log),{recursive:true});fs.writeFileSync(log,Buffer.concat([result.stdout||Buffer.alloc(0),result.stderr||Buffer.alloc(0)]));}
    if(result.error || result.status!==0) {
      const e=new Error(result.error?.message || result.stderr?.toString() || 'FABRIC_CLI_FAILED');e.fabricFailure=true;throw e;
    }
    return result.stdout;
  }
  query(method,payload) {
    const output=this.call(['chaincode','query','-C',this.channel,'-n',this.name,'--peerAddresses',this.endpoint,
      '--tlsRootCertFiles',this.tls(this.org),'-c',JSON.stringify({Args:[`LWFAContract:${method}`,m.canonicalJson(payload)]})]);
    return m.parseJson(utf8(output).trim());
  }
  qscc(method,...args) {
    const hex=this.call(['chaincode','query','-C',this.channel,'-n','qscc','--peerAddresses',this.endpoint,
      '--tlsRootCertFiles',this.tls(this.org),'--hex','-c',JSON.stringify({Args:[method,this.channel,...args]})]).toString().trim();
    ensure(/^(?:[0-9a-fA-F]{2})+$/.test(hex),'QSCC_HEX_REQUIRED');return Buffer.from(hex,'hex');
  }
  checkpoint() {const info=h.chainInfo(this.qscc('GetChainInfo'));return {channelID:this.channel,blockNumber:(info.height-1n).toString(),blockHeaderHash:info.hash};}
  snapshot(caseID,checkpoint,outdir) {
    ensure(this.role==='IndependentReviewer','ORG3_READER_REQUIRED');m.assertCheckpoint(checkpoint);
    ensure(checkpoint.channelID===this.channel,'SNAPSHOT_CHANNEL');
    const end=BigInt(checkpoint.blockNumber);ensure(end<4096n,'REPLAY_BLOCK_LIMIT_4096');
    const latest=this.checkpoint();ensure(BigInt(latest.blockNumber)>=end,'PEER_BEHIND_CHECKPOINT');
    const blocks=[];fs.mkdirSync(outdir,{recursive:true});
    for(let n=0n;n<=end;n++) {
      const raw=this.qscc('GetBlockByNumber',n.toString());blocks.push(raw);
      fs.writeFileSync(path.join(outdir,`block-${n}.pb`),raw);
    }
    const snapshot=h.replay(blocks,this.channel,this.name,caseID);
    ensure(snapshot.headers.at(-1).hash===checkpoint.blockHeaderHash,'SNAPSHOT_CHECKPOINT_HASH');
    writeJson(path.join(outdir,'summary.json'),{reader:this.actor,peer:this.endpoint,checkpoint,
      trustModel:'TLS_AUTHENTICATED_ORG3_PEER_VALIDATION_METADATA',headers:snapshot.headers,
      records:[...snapshot.records.values()],births:Object.fromEntries(snapshot.births),
      limits:['No independent endorsement/signature revalidation','Only selected public chaincode namespace replayed']});
    return snapshot;
  }
  record(caseID,recordID) {return this.query('GetRecord',{caseID,selector:{type:'RECORD',recordID}});}
  receipt(caseID,operationID) {return this.query('GetRecord',{caseID,selector:{type:'RECEIPT',actor:this.actor,operationID}});}
  submit(method,payload,outdir) {
    const validator={InitializeCase:m.validateInitializeInput,RegisterMaterial:m.validateRegisterInput,
      OpenReview:m.validateReviewInput,RegisterPackage:m.validatePackageInput,AppendObservation:m.validateObservationInput,RecordIssue:issues.validateIssueInput,RespondIssue:issues.validateResponseInput,DisposeIssue:issues.validateDispositionInput}[method];
    ensure(validator,'UNKNOWN_SUBMIT_METHOD');payload=validator(payload);
    const p=path.join(outdir,`${payload.operationID}.payload.json`);
    if(fs.existsSync(p))ensure(same(readJson(p),payload),'OUTBOX_INPUT_CHANGED');else writeJson(p,payload);
    const ctor={Args:[`LWFAContract:${method}`,m.canonicalJson(readJson(p))]};
    writeJson(path.join(outdir,`${payload.operationID}.ctor.json`),ctor);
    const {schemaVersion,caseID,operationID,...businessPayload}=payload;
    const expectedHash=m.hashJson('OPERATION',{operationName:method,schemaVersion,caseID,actor:this.actor,businessPayload});
    let receipt;
    try {receipt=this.receipt(caseID,operationID);}catch(error) {
      if(!/NOT_FOUND/.test(error.message))throw error;
    }
    if(!receipt) {
      const args=['chaincode','invoke','-o','localhost:7050','--ordererTLSHostnameOverride','orderer.example.com','--tls',
        '--cafile',path.join(this.tn,'organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem'),
        '-C',this.channel,'-n',this.name];
      for(const [org,port] of [[1,7051],[2,9051],[3,11051]])args.push('--peerAddresses',`localhost:${port}`,'--tlsRootCertFiles',this.tls(org));
      args.push('--waitForEvent','--waitForEventTimeout','60s','-c',JSON.stringify(ctor));
      // If submission times out, preserve the outbox. Retry recovers committed
      // receipt first; a new proposal must never change this logical payload.
      this.call(args,path.join(outdir,`${operationID}.invoke.log`));receipt=this.receipt(caseID,operationID);
    }
    ensure(receipt.inputHash===expectedHash && receipt.operationName===method && same(receipt.actor,this.actor),'RECEIPT_BINDING_MISMATCH');
    const raw=this.qscc('GetBlockByTxID',receipt.txID),block=h.decodeBlock(raw,this.channel,this.name);
    ensure(block.transactions.some(t=>t.valid && t.txID===receipt.txID),'RECEIPT_TX_NOT_COMMITTED_VALID');
    writeJson(path.join(outdir,`${operationID}.receipt.json`),receipt);
    return this.record(caseID,receipt.resultRef.recordID);
  }
}
module.exports={FabricClient,CONFIG};
