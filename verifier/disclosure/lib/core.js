'use strict';
// v070 keeps the on-chain v0.5.1 protocol; client parser corrections are
// separately recorded in RELEASE.json and source-origin.json.
const path = require('node:path');
const fs = require('node:fs');
const ROOT = path.resolve(process.env.LWFA_CORE_ROOT || path.join(__dirname, '..', '..', 'lwfa-p5-v0.2.0', 'vendor', 'lwfa-v0.5.1'));
if (!fs.existsSync(path.join(ROOT, 'client', 'package.js')) || !fs.existsSync(path.join(ROOT, 'chaincode', 'model.js')))
  throw new Error(`LWFA_CORE_NOT_FOUND: ${ROOT} (set LWFA_CORE_ROOT)`);
const req = rel => require(path.join(ROOT, rel));
module.exports = { ROOT, req };
