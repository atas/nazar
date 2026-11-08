#!/usr/bin/env node
const first = { pid: process.pid, has: Object.prototype.hasOwnProperty.call(process.env, 'SPIKE_SECRET'), cwd: process.cwd(), kind: 'esm' };
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
first.hash = first.has ? crypto.createHash('sha256').update(process.env.SPIKE_SECRET).digest('hex') : '';
first.nazarLeft = Object.keys(process.env).filter((k) => k.startsWith('NAZAR_'));
first.fds = fs.readdirSync('/proc/self/fd').map((f) => { try { return f + '=' + fs.readlinkSync('/proc/self/fd/' + f); } catch (e) { return f; } });
fs.writeFileSync(path.join(process.env.SPIKE_REPORT_DIR, 'target-' + process.pid + '.json'), JSON.stringify(first));
if (process.env.SPIKE_STAY) setInterval(() => {}, 1000);
