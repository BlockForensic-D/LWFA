'use strict';
const path = require('node:path');
const ROOT = path.resolve(__dirname, '..');
// This adapter uses the embedded v081 client rather than an external installation.
process.env.LWFA_CORE_ROOT = path.join(ROOT, 'vendor/core');
const req = rel => require(path.join(process.env.LWFA_CORE_ROOT, rel));
module.exports = {ROOT, req, io:req('client/io'), P:req('client/package'), H:req('client/history'),
  A:require('../vendor/disclosure/lib/assurance'),
  C:require('../vendor/disclosure/lib/creators'),
  CP:require('../vendor/disclosure/lib/checkpoint')};
