// nazar's Node loader (secrets design 6.3.1; 6.3 D1, D2). nazar-agent
// starts a `nazar run` receiver with NODE_OPTIONS="--require <this file>"
// and these variables, none of which holds a secret:
//
//   NAZAR_SECRET_NAMES  the variables to set, comma-separated
//   NAZAR_SECRET_SOCK   the per-run unix socket the agent serves them on
//   NAZAR_RUN_PID       the pid `nazar run` exec'd in
//   NAZAR_TARGET        for a launcher (npx) only: the package whose bin is
//                       the target
//
// The process the handover is for reads `NAME\tbase64(value)\n` lines from
// the socket before its first line of code runs, sets them in process.env
// and removes every trace of nazar from its environment, so the processes
// it starts never run this file again. Without NAZAR_TARGET that is the
// exec'd process itself; with it, a process that is not the exec'd one (the
// launcher) and whose main module is one of the target package's bin files
// (a dependency's install script is not). Every other process leaves
// everything as it is. A failure is one line on stderr, never the value,
// and the program starts without the variable.
'use strict';
(function nazarLateEnv() {
  const wt = require('worker_threads');
  // The worker below inherits NODE_OPTIONS; it must not run this again.
  if (!wt.isMainThread) return;
  const env = process.env;
  const names = (env.NAZAR_SECRET_NAMES || '').split(',').filter(Boolean);
  const sock = env.NAZAR_SECRET_SOCK;
  const runPid = env.NAZAR_RUN_PID;
  if (names.length === 0 || !sock || !runPid) return;
  const fs = require('fs');
  const path = require('path');
  const target = env.NAZAR_TARGET || '';
  const self = String(process.pid) === runPid;
  if (target ? self || !isBinOf(target) : !self) return;

  // isBinOf: the realpath of the main module is a bin file of the target
  // package, installed as the launcher's own top-level package: the first
  // node_modules in the path is the target's, and there is none after it.
  // A dependency's own copy of the package is not the target.
  function isBinOf(pkg) {
    try {
      if (!process.argv[1]) return false;
      const main = fs.realpathSync(process.argv[1]);
      const nm = path.sep + 'node_modules' + path.sep;
      const i = main.indexOf(nm);
      if (i < 0 || !main.startsWith(pkg + path.sep, i + nm.length)) return false;
      const root = main.slice(0, i + nm.length + pkg.length);
      if (main.indexOf(nm, root.length) >= 0) return false;
      const pj = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      if (pj.name !== pkg) return false;
      const bins = typeof pj.bin === 'string' ? [pj.bin] : Object.values(pj.bin || {});
      return bins.some((b) => {
        try {
          return typeof b === 'string' && fs.realpathSync(path.resolve(root, b)) === main;
        } catch (e) {
          return false;
        }
      });
    } catch (e) {
      return false;
    }
  }

  // forget removes every trace of nazar, so the program's own children
  // never run this file again. NODE_OPTIONS is the agent's alone (the
  // caller's is never passed), so it goes whole.
  function forget() {
    for (const k of ['NAZAR_SECRET_NAMES', 'NAZAR_SECRET_SOCK', 'NAZAR_RUN_PID', 'NAZAR_TARGET', 'NODE_OPTIONS']) delete env[k];
  }

  const reasons = {};
  try {
    const answer = read();
    for (const line of answer.data ? answer.data.toString('latin1').split('\n') : []) {
      const tab = line.indexOf('\t');
      const name = tab > 0 ? line.slice(0, tab) : '';
      const b64 = tab > 0 ? line.slice(tab + 1) : '';
      if (!names.includes(name) || name in reasons || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) continue;
      const v = Buffer.from(b64, 'base64');
      let s = null;
      try {
        s = new TextDecoder('utf-8', { fatal: true }).decode(v);
      } catch (e) {}
      v.fill(0);
      if (s === null || s.includes('\0')) {
        reasons[name] = "the value can't be an environment variable";
        continue;
      }
      env[name] = s;
      reasons[name] = '';
    }
    // The Buffers are cleared; the strings made from them can't be.
    if (answer.data) answer.data.fill(0);
    for (const n of names) if (!(n in reasons)) reasons[n] = answer.reason || 'nazar-agent did not send it';
  } catch (e) {
    for (const n of names) if (!(n in reasons)) reasons[n] = 'the loader failed';
  } finally {
    forget();
  }
  for (const n of names) {
    if (reasons[n]) process.stderr.write(`nazar: secret ${n} not delivered: ${reasons[n]}\n`);
  }

  // read reads the socket synchronously: the value must be in process.env
  // before the program's first line, and Node has no synchronous socket,
  // so a worker copies the answer into shared memory while this thread
  // waits. ctl[0] is the worker's state, ctl[1] the bytes it copied.
  function read() {
    // The worker's states, as the numbers it writes: 2 is any other failure.
    const WAITING = 0, DONE = 1, TOO_LONG = 3, NO_SOCKET = 4, CLOSED = 5;
    const max = 256 * 1024;
    const sab = new SharedArrayBuffer(8 + max);
    const ctl = new Int32Array(sab, 0, 2);
    const buf = new Uint8Array(sab, 8);
    const w = new wt.Worker(
      `const { workerData } = require('worker_threads');
       const net = require('net');
       const ctl = new Int32Array(workerData.sab, 0, 2);
       const buf = new Uint8Array(workerData.sab, 8);
       let n = 0;
       // Only while the main thread still waits (state 0): never after it
       // gave up and cleared the buffer.
       const end = (st) => { if (Atomics.compareExchange(ctl, 0, 0, st) === 0) { ctl[1] = n; Atomics.notify(ctl, 0); } };
       const s = net.connect(workerData.sock);
       s.on('data', (d) => {
         if (Atomics.load(ctl, 0) !== 0) { s.destroy(); return; }
         if (n + d.length > buf.length) { s.destroy(); end(3); return; }
         buf.set(d, n); n += d.length;
       });
       s.on('end', () => end(1));
       s.on('close', () => end(n > 0 ? 1 : 2));
       s.on('error', (e) => end(e && (e.code === 'ENOENT' || e.code === 'ECONNREFUSED') ? 4 : 2));`,
      { eval: true, workerData: { sab, sock }, env: wt.SHARE_ENV },
    );
    Atomics.wait(ctl, 0, WAITING, 130000);
    const st = Atomics.compareExchange(ctl, 0, WAITING, CLOSED);
    w.terminate();
    let out = { data: null, reason: '' };
    if (st === WAITING) out.reason = 'nazar-agent did not answer';
    else if (st === NO_SOCKET) out.reason = 'nazar-agent is not handing it over (no socket)';
    else if (st === TOO_LONG) out.reason = 'the answer was too long';
    else if (st !== DONE || ctl[1] === 0) out.reason = 'nazar-agent refused or closed the connection';
    else out.data = Buffer.from(buf.subarray(0, ctl[1]));
    buf.fill(0);
    return out;
  }
})();
