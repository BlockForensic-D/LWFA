'use strict';
// Controlled fixture parser. Counts result labels; no chronology inference.
const fs=require('node:fs');
try {
  if(process.argv.length!==3)throw new Error('one input file required');
  const bytes=fs.readFileSync(process.argv[2]);
  if(bytes.length>16*1024*1024)throw new Error('fixture exceeds size limit');
  const lines=new TextDecoder('utf-8',{fatal:true}).decode(bytes).split(/\r?\n/);
  const result={failedLoginCount:0,successfulLoginCount:0};
  for(const line of lines) {
    if(line==='result=denied')result.failedLoginCount++;
    if(line==='result=success')result.successfulLoginCount++;
  }
  process.stdout.write(JSON.stringify(result)+'\n');
} catch(error) {process.stderr.write(error.message+'\n');process.exitCode=2;}
