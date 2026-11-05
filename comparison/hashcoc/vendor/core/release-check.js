'use strict';

// Local source/package checks. No network, enrollment, or ledger mutations.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const root = __dirname;
const model = require('./chaincode/model');
const mode = process.argv[2] || 'check';

function ensure(condition, message) {
  if (!condition) throw new Error(message);
}
function sha(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function collect(folder, relative = '') {
  return fs.readdirSync(folder, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))
    .flatMap(entry => {
      if (['node_modules', 'results', '.git'].includes(entry.name)) return [];
      const rel = path.posix.join(relative, entry.name);
      return entry.isDirectory() ? collect(path.join(folder, entry.name), rel) : [rel];
    });
}
function readJson(file) { return model.parseJson(fs.readFileSync(path.join(root, file), 'utf8')); }
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 20000, ...options });
  ensure(!result.error && result.status === 0,
    `${command} ${args.join(' ')} failed: ${result.error?.message || result.stderr || result.stdout}`);
  return result.stdout;
}
function inspect() {
  const sources = collect(root);
  const javascript = sources.filter(file => /\.(?:js|cjs)$/.test(file));
  for (const file of javascript) run(process.execPath, ['--check', path.join(root, file)]);
  const profiles = model.getSupportedProfiles().map(profile => profile.ref);
  const app = readJson('package.json'); const cc = readJson('chaincode/package.json');
  const lock = readJson('chaincode/package-lock.json'); const rootLock = readJson('package-lock.json');
  ensure(app.version === cc.version && lock.version === cc.version && lock.packages[''].version === cc.version,
    'release and chaincode lock versions differ');
  ensure(rootLock.version === app.version && rootLock.packages[''].version === app.version,
    'root lock version differs');
  ensure(model.canonicalJson(cc.dependencies) === model.canonicalJson(lock.packages[''].dependencies),
    'dependency manifest differs from lockfile');
  for (const [name, version] of Object.entries(cc.dependencies)) {
    ensure(lock.packages[`node_modules/${name}`]?.version === version, `unlocked dependency ${name}`);
  }
  const source = fs.readFileSync(path.join(root, 'chaincode/LWFAContract.js'), 'utf8');
  const methods = [...source.matchAll(/^  async ([A-Z]\w+)\(ctx, inputJson\)/gm)].map(match => match[1]);
  const expected = ['InitializeCase', 'RegisterMaterial', 'OpenReview', 'RegisterPackage', 'AppendObservation',
    'GetCase', 'GetMaterialVersion', 'GetRecord', 'ListCaseJournal', 'RecordIssue', 'RespondIssue', 'DisposeIssue', 'GetIssueHead'];
  ensure(model.canonicalJson(methods.slice().sort()) === model.canonicalJson(expected.slice().sort()),
    'public method inventory differs');
  for (const method of methods) ensure(source.includes(`['${method}', `), `missing SDK annotation ${method}`);
  for (const file of sources.filter(p => p.startsWith('chaincode/') && p.endsWith('.js'))) {
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    ensure(!text.includes('sdk-isolation') && !text.includes("require('../tests"), 'test code leaked into contract');
    for (const match of text.matchAll(/require\(['"](\.[^'"]+)['"]\)/g)) {
      const resolved = path.resolve(path.dirname(path.join(root, file)), match[1]);
      ensure(resolved.startsWith(path.join(root, 'chaincode') + path.sep), `external local import in ${file}`);
    }
  }
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'lwfa-package-'));
  try {
    const names = ['index.js', 'model.js', 'state.js', 'issues.js', 'LWFAContract.js', 'profiles.json', 'package.json', 'package-lock.json'];
    for (const name of names) fs.copyFileSync(path.join(root, 'chaincode', name), path.join(temporary, name));
    const isolated = run(process.execPath, ['-e', "const m=require('./model');console.log(JSON.stringify(m.getSupportedProfiles().map(p=>p.ref)))"], { cwd: temporary });
    ensure(model.canonicalJson(JSON.parse(isolated)) === model.canonicalJson(profiles), 'standalone profile definitions differ');
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
  return { release: app.version, node: process.version, checks: {
    syntaxFiles: javascript.length, packageLocks: 'CONSISTENT', profileDefinitions: 'MATCH',
    publicMethods: methods, sourcePackage: 'SELF_CONTAINED_LOCAL_IMPORTS',
    sdkMetadata: 'NOT_CHECKED', fabricNetwork: 'NOT_CHECKED',
  }, profiles, files: Object.fromEntries(sources.map(file => [file, sha(fs.readFileSync(path.join(root, file)))])) };
}
try {
  if (mode === 'profiles') {
    console.log(JSON.stringify(model.getSupportedProfiles().map(profile => profile.ref), null, 2));
  } else {
    ensure(['check', 'manifest'].includes(mode), 'usage: node release-check.js [check|profiles|manifest]');
    const report = inspect();
    if (mode === 'manifest') {
      const destination = path.join(root, 'results/source-manifest.json');
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, JSON.stringify(report, null, 2) + '\n');
      console.log('results/source-manifest.json');
    } else console.log(JSON.stringify({ release: report.release, node: report.node, checks: report.checks, profiles: report.profiles }, null, 2));
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
