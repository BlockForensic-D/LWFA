'use strict';
// Bounded text extraction only. This tool never evaluates commands in evidence.
const fs=require('node:fs'),crypto=require('node:crypto');
const TARGET='/tmp/.X11-unix/.xorg';
function extract(input){
  if(!Buffer.isBuffer(input)||input.length>1048576)throw Error('INPUT_LIMIT');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(input);
  const lines=text.split(/\r\n|\n|\r/);if(lines.at(-1)==='')lines.pop();
  const references=[],directives=[];
  for(let i=0;i<lines.length;i++){
    const line=lines[i],trimmed=line.trim();
    if(trimmed.startsWith('#')||trimmed.startsWith(';'))continue;
    if(line.includes(TARGET))references.push({line:i+1,text:line,
      before:i?lines[i-1]:null,after:i+1<lines.length?lines[i+1]:null});
    if(/^(Description|ExecStart|Restart|WantedBy)=/.test(trimmed))directives.push({line:i+1,text:line});
  }
  return {format:'LWFA_PERSISTENCE_LINES_1',inputSHA256:crypto.createHash('sha256').update(input).digest('hex'),
    byteLength:input.length,lineCount:lines.length,target:TARGET,references,directives};
}
if(require.main===module){
  try{
    if(process.argv.length!==3)throw Error('ONE_INPUT_PATH_REQUIRED');
    const fd=fs.openSync(process.argv[2],fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    let bytes;try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>1048576)throw Error('INPUT_LIMIT');bytes=fs.readFileSync(fd);}finally{fs.closeSync(fd);}
    process.stdout.write(JSON.stringify(extract(bytes))+'\n');
  }catch(e){process.stderr.write(e.message+'\n');process.exitCode=1;}
}
module.exports={extract,TARGET};
