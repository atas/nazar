// S12 spike: the Node side of the late-env handover. THROWAWAY (spikes/README.md).
// Loaded with NODE_OPTIONS="--require <abs>/loader.cjs". Writes a report per process
// to $SPIKE_REPORT_DIR so the driver can see which process ran it and what it got.
'use strict';
(function () {
  const wt = require('worker_threads');
  if (!wt.isMainThread) return;
  const env = process.env;
  const names = env.NAZAR_SECRET_NAMES;
  if (!names) return;
  const fs = require('fs');
  const path = require('path');
  const crypto = require('crypto');
  const rep = {
    pid: process.pid, ppid: process.ppid, argv: process.argv, execPath: process.execPath,
    execArgv: process.execArgv, cwd: process.cwd(), nodeOptions: env.NODE_OPTIONS || '',
    fd3: (() => { try { return fs.readlinkSync('/proc/self/fd/3'); } catch (e) { return 'EBADF'; } })(),
    via: env.SPIKE_VIA || 'require', matched: false, got: {}, error: '', t0: Date.now(),
  };
  const write = () => {
    try { fs.writeFileSync(path.join(env.SPIKE_REPORT_DIR, `node-${process.pid}-${Date.now()}.json`), JSON.stringify(rep)); } catch (e) {}
  };
  if (String(process.pid) === env.NAZAR_LAUNCHER_PID) {
    // The exec'd launcher itself: leave everything for its children, drop the marker
    // so an image this pid execs later is not mistaken for the launcher.
    delete env.NAZAR_LAUNCHER_PID;
    rep.skip = 'launcher pid';
    write();
    return;
  }
  const target = env.NAZAR_TARGET || '';
  const main = process.argv[1] ? (() => { try { return fs.realpathSync(process.argv[1]); } catch (e) { return process.argv[1]; } })() : '';
  rep.mainReal = main;
  if (target) {
    // package-root rule: the main module is inside node_modules/<target>/ with no deeper node_modules.
    const marker = '/node_modules/' + target + '/';
    const i = main.lastIndexOf(marker);
    if (i < 0 || main.indexOf('/node_modules/', i + marker.length - 1) >= 0) { rep.skip = 'target'; write(); return; }
    // bin rule: the main module is one of the package's own bin files.
    const root = main.slice(0, i + marker.length - 1);
    let bins = [];
    try {
      const pj = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      bins = typeof pj.bin === 'string' ? [pj.bin] : Object.values(pj.bin || {});
    } catch (e) {}
    const real = bins.map((b) => { try { return fs.realpathSync(path.join(root, b)); } catch (e) { return ''; } });
    rep.bins = real;
    if (!real.includes(main)) { rep.skip = 'not a bin of ' + target; write(); return; }
  }
  rep.matched = true;
  let data = null;
  try {
    if (env.NAZAR_SECRET_FD) {
      const fd = Number(env.NAZAR_SECRET_FD);
      data = fs.readFileSync(fd);
      fs.closeSync(fd);
    } else if (env.NAZAR_SECRET_SOCK) {
      const sab = new SharedArrayBuffer(8 + (256 << 10));
      const ctl = new Int32Array(sab, 0, 2);
      const buf = new Uint8Array(sab, 8);
      const w = new wt.Worker(`
        const { workerData } = require('worker_threads');
        const net = require('net');
        const ctl = new Int32Array(workerData.sab, 0, 2);
        const buf = new Uint8Array(workerData.sab, 8);
        let n = 0, done = (st) => { ctl[1] = n; Atomics.store(ctl, 0, st); Atomics.notify(ctl, 0); };
        const s = net.connect(workerData.path);
        s.on('data', (d) => { if (n + d.length > buf.length) { s.destroy(); done(3); return; } buf.set(d, n); n += d.length; });
        s.on('end', () => done(1));
        s.on('error', () => done(2));
      `, { eval: true, workerData: { sab, path: env.NAZAR_SECRET_SOCK }, env: wt.SHARE_ENV });
      const r = Atomics.wait(ctl, 0, 0, Number(env.SPIKE_TIMEOUT_MS || 120000));
      w.terminate();
      if (r === 'timed-out' || Atomics.load(ctl, 0) !== 1) throw new Error('socket handover failed: ' + r + '/' + Atomics.load(ctl, 0));
      data = Buffer.from(buf.subarray(0, ctl[1]));
      buf.fill(0);
    }
    for (const line of data.toString('latin1').split('\n')) {
      if (!line) continue;
      const [name, b64] = line.split('\t');
      const v = Buffer.from(b64, 'base64');
      rep.got[name] = crypto.createHash('sha256').update(v).digest('hex');
      process.env[name] = v.toString('utf8');
    }
  } catch (e) { rep.error = String(e); }
  for (const k of ['NAZAR_SECRET_NAMES', 'NAZAR_TARGET', 'NAZAR_SECRET_FD', 'NAZAR_SECRET_SOCK', 'NAZAR_LAUNCHER_PID']) delete env[k];
  if (env.NODE_OPTIONS) {
    const rest = env.NODE_OPTIONS.replace(/--(require|import)[ =]\S+/g, '').trim();
    if (rest) env.NODE_OPTIONS = rest; else delete env.NODE_OPTIONS;
  }
  rep.t1 = Date.now();
  write();
})();
