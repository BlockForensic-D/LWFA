'use strict';
// Bounded Fabric protobuf decoder. Only the selected public namespace is replayed.
// Validation flags are trusted from an authenticated Org3 peer, NOT authenticated
// by the block-header hash. This is not independent consensus/MSP verification.
const issueSchema = require('../chaincode/issues');
const { m, ensure, sha, utf8, same } = require('./io');
function fields(bytes) {
  ensure(Buffer.isBuffer(bytes) && bytes.length <= 32*1024*1024, 'PROTO_SIZE');
  let p=0; const out=new Map();
  function variable() {
    let n=0n;
    for(let i=0;i<10;i++) {
      ensure(p<bytes.length,'PROTO_TRUNCATED'); const b=bytes[p++];
      if(i===9) ensure(b<=1,'PROTO_VARINT_OVERFLOW');
      n |= BigInt(b&127)<<BigInt(7*i); if(!(b&128)) return n;
    }
    throw new Error('PROTO_VARINT_OVERFLOW');
  }
  while(p<bytes.length) {
    const tag=variable(), number=Number(tag>>3n), wire=Number(tag&7n);
    ensure(number>0 && number<536870912, 'PROTO_FIELD'); let value;
    if(wire===0) value=variable();
    else {
      let length;
      if(wire===2) { const n=variable(); ensure(n<=BigInt(bytes.length),'PROTO_LENGTH'); length=Number(n); }
      else if(wire===1) length=8;
      else if(wire===5) length=4;
      else throw new Error('PROTO_WIRE_UNSUPPORTED');
      ensure(p+length<=bytes.length,'PROTO_TRUNCATED'); value=bytes.subarray(p,p+length); p+=length;
    }
    if(!out.has(number)) out.set(number,[]); out.get(number).push({wire,value});
  }
  return out;
}
function one(msg, n, wire=2, optional=false) {
  const a=msg.get(n)||[]; ensure(a.length<=1,'PROTO_DUPLICATE_FIELD');
  if(a.length===0) { ensure(optional,'PROTO_REQUIRED_FIELD'); return wire===0?0n:Buffer.alloc(0); }
  ensure(a[0].wire===wire,'PROTO_WIRE_TYPE'); return a[0].value;
}
function many(msg,n) { return (msg.get(n)||[]).map(v=>{ensure(v.wire===2,'PROTO_WIRE_TYPE');return v.value;}); }
const msg=(p,n,optional=false)=>fields(one(p,n,2,optional));
function der(tag, bytes) {
  const n=bytes.length;
  const length=n<128?Buffer.from([n]):(()=>{let h=n.toString(16);if(h.length%2)h='0'+h;const b=Buffer.from(h,'hex');return Buffer.concat([Buffer.from([128|b.length]),b]);})();
  return Buffer.concat([Buffer.from([tag]),length,bytes]);
}
function headerHash(number,prev,data) {
  let h=number.toString(16); if(h.length%2)h='0'+h;
  let b=Buffer.from(h,'hex'); if(b[0]&128)b=Buffer.concat([Buffer.from([0]),b]);
  return sha(der(48,Buffer.concat([der(2,b),der(4,prev),der(4,data)])));
}
function decodeBlock(raw, channel, namespace) {
  const root=fields(raw), header=msg(root,1), number=one(header,1,0,true);
  const previous=one(header,2,2,true), dataHash=one(header,3);
  const envelopes=many(msg(root,2),1), metadata=many(msg(root,3),1), flags=metadata[2];
  ensure(flags && flags.length===envelopes.length,'PEER_VALIDATION_METADATA_REQUIRED');
  ensure(dataHash.length===32 && sha(Buffer.concat(envelopes))===dataHash.toString('hex'),'BLOCK_DATA_HASH_MISMATCH');
  const transactions=[];
  envelopes.forEach((rawEnvelope,index)=>{
    // Invalid transactions cannot contribute records or update the snapshot.
    if(flags[index]!==0) {transactions.push({index,valid:false,code:flags[index],writes:[]});return;}
    const payload=msg(fields(rawEnvelope),1), hdr=msg(msg(payload,1),1);
    const channelID=utf8(one(hdr,4)); ensure(channelID===channel,'BLOCK_CHANNEL_MISMATCH');
    const txID=utf8(one(hdr,5,2,true)), type=Number(one(hdr,1,0,true)), writes=[];
    if(type===3) {
      for(const rawAction of many(msg(payload,2),1)) {
        const actionPayload=msg(fields(rawAction),2);
        const endorsed=msg(actionPayload,2), response=msg(endorsed,1), extension=msg(response,2);
        const rw=msg(extension,1); ensure(one(rw,1,0,true)===0n,'UNSUPPORTED_RW_MODEL');
        for(const rawNS of many(rw,2)) {
          const ns=fields(rawNS); if(utf8(one(ns,1))!==namespace)continue;
          const kv=msg(ns,2);
          for(const rawWrite of many(kv,3)) {
            const w=fields(rawWrite); writes.push({key:utf8(one(w,1)),deleted:one(w,2,0,true)!==0n,value:one(w,3,2,true)});
          }
        }
      }
    } else ensure(type===1 || type===2, 'UNSUPPORTED_VALID_TRANSACTION_TYPE');
    transactions.push({index,valid:true,txID,type,writes});
  });
  return {number:number.toString(),hash:headerHash(number,previous,dataHash),previousHash:previous.toString('hex'),transactions};
}
function replay(blocks, channel, namespace, caseID) {
  const records=new Map(), births=new Map(), transactions=new Map(); let previous=''; const headers=[];
  blocks.forEach((raw,i)=>{
    const b=decodeBlock(raw,channel,namespace); ensure(BigInt(b.number)===BigInt(i),'BLOCK_SEQUENCE_MISMATCH');
    ensure(b.previousHash===previous,'BLOCK_HASH_CHAIN_MISMATCH'); previous=b.hash;
    headers.push({number:b.number,hash:b.hash});
    for(const tx of b.transactions) {
      if(!tx.valid)continue;
      if(tx.txID) {ensure(!transactions.has(tx.txID),'DUPLICATE_VALID_TXID');transactions.set(tx.txID,{block:b.number,index:tx.index});}
      for(const w of tx.writes) {
        const parts=w.key.split('\0');
        if(parts[1]!=='lwfa.record' || parts[2]!==caseID)continue;
        ensure(parts.length===5 && !w.deleted,'UNSUPPORTED_RECORD_DELETE_OR_KEY');
        const e=m.parseJson(utf8(w.value)); m.verifyEnvelopeCommitment(e);
        ensure(e.caseID===caseID && e.recordID===parts[3], 'REPLAY_KEY_BINDING');
        ensure(['CASE_CONFIG','MATERIAL_VERSION','REVIEW_REQUEST','PACKAGE_RECORD','OBSERVATION','ISSUE','ISSUE_RESPONSE','ISSUE_DISPOSITION'].includes(e.kind),'UNSUPPORTED_RECORD_KIND');
        if(e.kind==='ISSUE') issueSchema.validateIssueBody(e.body,caseID);
        if(e.kind==='ISSUE_RESPONSE') issueSchema.validateResponseBody(e.body,caseID,true);
        if(e.kind==='ISSUE_DISPOSITION') issueSchema.validateDispositionBody(e.body,caseID,true);
        if(records.has(e.recordID))ensure(same(records.get(e.recordID),e),'RECORD_OVERWRITE');
        else {records.set(e.recordID,e);births.set(e.recordID,{block:b.number,index:tx.index,txID:tx.txID});}
      }
    }
  });
  return {records,births,transactions,headers};
}
function chainInfo(raw) {
  const o=fields(raw); const height=one(o,1,0); ensure(height>0n,'EMPTY_CHANNEL');
  return {height,hash:one(o,2).toString('hex')};
}
module.exports={fields,one,many,msg,headerHash,decodeBlock,replay,chainInfo};
