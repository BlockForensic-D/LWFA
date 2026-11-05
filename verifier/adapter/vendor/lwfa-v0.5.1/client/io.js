'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const m = require('../chaincode/model');
const utf8 = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
function ensure(ok, message) { if (!ok) throw new Error(message); }
class PackageInputError extends Error {
  constructor(code,bindingFailure=false) {super(code);this.name='PackageInputError';this.code=code;this.inputFailure=true;this.bindingFailure=bindingFailure;}
}
const INPUT_CODES=new Set(['UNSAFE_PACKAGE_PATH','PACKAGE_SYMLINK','PACKAGE_ROOT_TYPE','INVALID_PACKAGE_FILE',
  'UNLISTED_PACKAGE_FILE','UNLISTED_PACKAGE_DIRECTORY','PACKAGE_FILE_COUNT_LIMIT','PACKAGE_TOTAL_SIZE_LIMIT',
  'FILE_TYPE_OR_SIZE','DUPLICATE_PACKAGE_PATH','TOOL_HASH_MISMATCH']);
function inputCheck(fn) {
  try {return fn();} catch(e) {
    if(INPUT_CODES.has(e.message)||e.code==='SCHEMA_ERROR'||e.code==='ERR_ENCODING_INVALID_ENCODED_DATA')
      throw new PackageInputError(e.code==='SCHEMA_ERROR'?'MANIFEST_SCHEMA_ERROR':e.message);
    throw e;
  }
}
function sha(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function readJson(file) { return m.parseJson(utf8(fs.readFileSync(file))); }
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, m.canonicalJson(value)); fs.renameSync(temp, file);
}
function same(a,b) { return m.canonicalJson(a) === m.canonicalJson(b); }
function safeRelative(relative) {
  ensure(typeof relative === 'string' && !relative.includes('\\') && !relative.includes('\0') &&
    !path.isAbsolute(relative) && relative.split('/').every(v => v && v !== '.' && v !== '..'), 'UNSAFE_PACKAGE_PATH');
  return relative;
}
function safeFile(root, relative) {
  safeRelative(relative);
  const base = fs.realpathSync(root); let current = base;
  for (const item of relative.split('/')) {
    current = path.join(current, item); ensure(!fs.lstatSync(current).isSymbolicLink(), 'PACKAGE_SYMLINK');
  }
  ensure(current.startsWith(base + path.sep) && fs.statSync(current).isFile(), 'INVALID_PACKAGE_FILE');
  return current;
}
// Local package directories must be immutable during verification. The limits
// bound this research adapter; they are not a general-purpose archive format.
const PACKAGE_LIMITS = Object.freeze({files:512, totalBytes:128*1024*1024, blobBytes:16*1024*1024, manifestBytes:1024*1024});
function packageInventory(root, relativePaths) {
  ensure(Array.isArray(relativePaths) && relativePaths.length + 1 <= PACKAGE_LIMITS.files, 'PACKAGE_FILE_COUNT_LIMIT');
  const allowed = new Set(['manifest.json']), dirs = new Set();
  for (const rel of relativePaths) {
    safeRelative(rel); ensure(!allowed.has(rel), 'DUPLICATE_PACKAGE_PATH'); allowed.add(rel);
    const parts=rel.split('/');for(let i=1;i<parts.length;i++)dirs.add(parts.slice(0,i).join('/'));
  }
  const st=fs.lstatSync(root);ensure(!st.isSymbolicLink() && st.isDirectory(), 'PACKAGE_ROOT_TYPE');
  let count=0,totalBytes=0;const present=[];
  function walk(folder,prefix='') {
    for(const entry of fs.readdirSync(folder,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:1)) {
      const rel=prefix+entry.name, full=path.join(folder,entry.name), stat=fs.lstatSync(full);
      ensure(!stat.isSymbolicLink(),'PACKAGE_SYMLINK');
      if(stat.isDirectory()) {ensure(dirs.has(rel),'UNLISTED_PACKAGE_DIRECTORY');walk(full,rel+'/');continue;}
      ensure(stat.isFile(),'INVALID_PACKAGE_FILE');ensure(allowed.has(rel),'UNLISTED_PACKAGE_FILE');
      ensure(++count<=PACKAGE_LIMITS.files,'PACKAGE_FILE_COUNT_LIMIT');
      ensure(stat.size<=(rel==='manifest.json'?PACKAGE_LIMITS.manifestBytes:PACKAGE_LIMITS.blobBytes),'FILE_TYPE_OR_SIZE');
      totalBytes+=stat.size;ensure(totalBytes<=PACKAGE_LIMITS.totalBytes,'PACKAGE_TOTAL_SIZE_LIMIT');present.push(rel);
    }
  }
  walk(root);return {present,totalBytes,missing:[...allowed].filter(f=>!present.includes(f))};
}
function fileBytes(file, maximum = 16*1024*1024) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd); ensure(st.isFile() && st.size <= maximum, 'FILE_TYPE_OR_SIZE');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}
// Rejected manifests can exceed the parsing limit. Hashing uses one descriptor,
// bounded memory, and a hard read limit; digest failures are operational errors.
function rejectedFileDigest(file, maximum = PACKAGE_LIMITS.totalBytes) {
  const fail=code=>{const e=new Error(code);e.code=code;throw e;};
  if(!Number.isSafeInteger(maximum)||maximum<0||maximum>PACKAGE_LIMITS.totalBytes)fail('REJECTION_DIGEST_LIMIT_INVALID');
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
    const before=fs.fstatSync(fd);
    if(!before.isFile())fail('REJECTION_DIGEST_FILE_TYPE');
    if(before.size>maximum)fail('REJECTION_DIGEST_SIZE_LIMIT');
    const hash=crypto.createHash('sha256'),chunk=Buffer.alloc(64*1024);let total=0,n;
    while((n=fs.readSync(fd,chunk,0,Math.min(chunk.length,maximum-total+1),null))>0){
      total+=n;if(total>maximum)fail('REJECTION_DIGEST_SIZE_LIMIT');hash.update(chunk.subarray(0,n));
    }
    const after=fs.fstatSync(fd);
    if(total!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)
      fail('REJECTION_DIGEST_FILE_CHANGED');
    return hash.digest('hex');
  } finally {fs.closeSync(fd);}
}
module.exports = { fs, path, m, utf8, ensure, sha, readJson, writeJson, same, safeRelative, safeFile, fileBytes, rejectedFileDigest, packageInventory, PACKAGE_LIMITS, PackageInputError, inputCheck };
