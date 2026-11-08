#!/usr/bin/env node
// First line of the target: is the secret already in process.env?
const first = { pid: process.pid, has: Object.prototype.hasOwnProperty.call(process.env, 'SPIKE_SECRET'), cwd: process.cwd(), kind: 'cjs' };
require('./report.js')(first);
