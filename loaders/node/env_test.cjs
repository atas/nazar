// Tests of loaders/node/env.cjs: `node --test loaders/node/`.
// Each test starts real node processes with the loader in NODE_OPTIONS, as
// nazar-agent does, and plays the agent on a real unix socket.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const LOADER = path.join(__dirname, 'env.cjs');
const NODE_OPTIONS = '--require ' + JSON.stringify(LOADER);

function tmp() {
  return fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'nzl-'));
}

// serve answers every connection with lines (or by closing), recording the
// connections; close() stops it.
function serve(dir, answer, t) {
  const sock = path.join(dir, 's.sock');
  const conns = [];
  const srv = net.createServer((c) => {
    c.on('error', () => {}); // a loader that hangs up early resets the connection
    conns.push(c);
    const a = answer(conns.length);
    if (a === null) c.destroy();
    else c.end(a);
  });
  const close = () => srv.close();
  if (t) {
    t.after(() => {
      close();
      fs.rmSync(dir, { recursive: true, force: true });
    });
  }
  return new Promise((resolve) => srv.listen(sock, () => resolve({ sock, conns, close })));
}

function line(name, value) {
  return name + '\t' + Buffer.from(value).toString('base64') + '\n';
}

// run starts `sh -c 'NAZAR_RUN_PID=$$; exec node <script>'` (the pid the CLI
// exec'd in) with a clean environment plus env, and resolves with its
// report (the script's first line writes one), stderr and exit code.
function run(script, env, opts = {}) {
  const nodeOptions = opts.nodeOptions || NODE_OPTIONS;
  const dir = path.dirname(script);
  const report = path.join(dir, 'report-' + crypto.randomBytes(4).toString('hex') + '.json');
  const full = {
    PATH: process.env.PATH,
    HOME: os.homedir(),
    NODE_OPTIONS: nodeOptions,
    REPORT: report,
    ...env,
  };
  const pidVar = opts.notRunPid ? 'NAZAR_RUN_PID=1' : 'NAZAR_RUN_PID=$$';
  const args = opts.args || [];
  const child = spawn('/bin/sh', ['-c', `export ${pidVar}; exec "$@"`, 'sh', process.execPath, script, ...args], {
    env: full,
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: '/',
  });
  let stderr = '';
  child.stderr.on('data', (d) => (stderr += d));
  return new Promise((resolve) => {
    child.on('exit', (code) => {
      let rep = null;
      try {
        rep = JSON.parse(fs.readFileSync(report, 'utf8'));
      } catch (e) {}
      resolve({ rep, stderr, code, pid: child.pid });
    });
  });
}

// A target script whose first line records what it sees.
const PROBE = `
const first = { has: process.env.SECRET_X, pid: process.pid,
  nazar: Object.keys(process.env).filter((k) => k.startsWith('NAZAR_')), nodeOptions: process.env.NODE_OPTIONS,
  other: process.env.OTHER, injected: process.env.INJECTED };
require('fs').writeFileSync(process.env.REPORT, JSON.stringify(first));
`;

test('the exec\'d interpreter gets the value before its first line, and nazar leaves no trace', async () => {
  const dir = tmp();
  const s = await serve(dir, () => line('SECRET_X', 'v4lue with spaces\nand a newline'));
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  s.close();
  assert.strictEqual(r.code, 0, r.stderr);
  assert.strictEqual(r.rep.has, 'v4lue with spaces\nand a newline');
  assert.deepStrictEqual(r.rep.nazar, []);
  assert.strictEqual(r.rep.nodeOptions, undefined);
  assert.strictEqual(s.conns.length, 1);
  assert.strictEqual(r.stderr, '');
});

test('an ESM target gets it before its first line too', async () => {
  const dir = tmp();
  const s = await serve(dir, () => line('SECRET_X', 'esm'));
  const script = path.join(dir, 'server.mjs');
  fs.writeFileSync(script, `import fs from 'fs';\n${PROBE.replace("require('fs')", 'fs')}`);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  s.close();
  assert.strictEqual(r.rep.has, 'esm', r.stderr);
});

test('another process (not the exec\'d one, no target) does nothing and keeps the variables', async () => {
  const dir = tmp();
  const s = await serve(dir, () => line('SECRET_X', 'no'));
  const script = path.join(dir, 'other.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock }, { notRunPid: true });
  s.close();
  assert.strictEqual(r.rep.has, undefined);
  assert.strictEqual(s.conns.length, 0);
  assert.deepStrictEqual(r.rep.nazar.sort(), ['NAZAR_RUN_PID', 'NAZAR_SECRET_NAMES', 'NAZAR_SECRET_SOCK']);
  assert.strictEqual(r.rep.nodeOptions, NODE_OPTIONS);
});

// A fake npm install: node_modules/<pkg> with a bin, an install script
// beside it, and a dependency nested under it with a bin of the same name.
function project(dir, pkg) {
  const root = path.join(dir, 'node_modules', pkg);
  fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: pkg, bin: { srv: 'dist/index.js' } }));
  fs.writeFileSync(path.join(root, 'dist', 'index.js'), PROBE);
  fs.writeFileSync(path.join(root, 'install.js'), PROBE);
  const nested = path.join(root, 'node_modules', 'dep');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(path.join(nested, 'package.json'), JSON.stringify({ name: pkg, bin: 'bin.js' }));
  fs.writeFileSync(path.join(nested, 'bin.js'), PROBE);
  fs.mkdirSync(path.join(dir, 'node_modules', '.bin'), { recursive: true });
  fs.symlinkSync(path.join(root, 'dist', 'index.js'), path.join(dir, 'node_modules', '.bin', 'srv'));
  return root;
}

test('under a launcher only a bin of the target package takes the handover', async () => {
  const dir = tmp();
  const root = project(dir, '@brave/brave-search-mcp-server');
  const s = await serve(dir, () => line('SECRET_X', 'brave'));
  const env = { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock, NAZAR_TARGET: '@brave/brave-search-mcp-server' };
  // The launcher itself (the exec'd pid) runs the loader first and must
  // neither connect nor change anything its children inherit.
  const launcher = await run(path.join(root, 'dist', 'index.js'), env);
  assert.strictEqual(launcher.rep.has, undefined);
  assert.strictEqual(launcher.rep.nodeOptions, NODE_OPTIONS);
  // The package's own install script and a nested dependency's bin are
  // not the target.
  for (const p of [path.join(root, 'install.js'), path.join(root, 'node_modules', 'dep', 'bin.js')]) {
    const r = await run(p, env, { notRunPid: true });
    assert.strictEqual(r.rep.has, undefined, p);
  }
  assert.strictEqual(s.conns.length, 0);
  // The bin, reached through node_modules/.bin as npm runs it, is.
  const r = await run(path.join(dir, 'node_modules', '.bin', 'srv'), env, { notRunPid: true });
  s.close();
  assert.strictEqual(r.rep.has, 'brave', r.stderr);
  assert.deepStrictEqual(r.rep.nazar, []);
  assert.strictEqual(s.conns.length, 1);
});

test('a package.json naming another package does not make its bin the target', async () => {
  const dir = tmp();
  const root = project(dir, 'good');
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'evil', bin: 'dist/index.js' }));
  const s = await serve(dir, () => line('SECRET_X', 'x'));
  const r = await run(path.join(root, 'dist', 'index.js'), { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock, NAZAR_TARGET: 'good' }, { notRunPid: true });
  s.close();
  assert.strictEqual(r.rep.has, undefined);
  assert.strictEqual(s.conns.length, 0);
});

test('only the names nazar asked for are set, each once', async () => {
  const dir = tmp();
  const s = await serve(dir, () => line('INJECTED', 'x') + line('NODE_OPTIONS', '--require /tmp/evil.js') + line('SECRET_X', 'one') + line('SECRET_X', 'two') + 'SECRET_X\t%%%\n');
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  s.close();
  assert.strictEqual(r.rep.has, 'one');
  assert.strictEqual(r.rep.injected, undefined);
  assert.strictEqual(r.rep.nodeOptions, undefined);
});

test('a refusal is one line on stderr, never a value, and the program still starts', async () => {
  const dir = tmp();
  const s = await serve(dir, () => null);
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  s.close();
  assert.strictEqual(r.code, 0);
  assert.strictEqual(r.rep.has, undefined);
  assert.deepStrictEqual(r.rep.nazar, []);
  assert.match(r.stderr, /^nazar: secret SECRET_X not delivered: nazar-agent refused or closed the connection\n$/);
  // No socket at all.
  const r2 = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: path.join(dir, 'gone.sock') });
  assert.strictEqual(r2.rep.has, undefined);
  assert.match(r2.stderr, /not delivered: nazar-agent is not handing it over/);
});

test('a worker thread of the target never runs the loader again', async () => {
  const dir = tmp();
  const s = await serve(dir, () => line('SECRET_X', 'w'));
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, `const { Worker } = require('worker_threads');
new Worker('require("fs").appendFileSync(process.env.REPORT + ".w", "ran")', { eval: true }).on('exit', () => {
  require('fs').writeFileSync(process.env.REPORT, JSON.stringify({ has: process.env.SECRET_X }));
});`);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  s.close();
  assert.strictEqual(r.rep.has, 'w');
  assert.strictEqual(s.conns.length, 1);
  assert.strictEqual(fs.readFileSync(r.rep && path.join(dir, fs.readdirSync(dir).find((f) => f.endsWith('.json.w'))), 'utf8'), 'ran');
});

test('without the variables the loader does nothing', async () => {
  const dir = tmp();
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { OTHER: 'kept' });
  assert.strictEqual(r.rep.other, 'kept');
  assert.strictEqual(r.rep.nodeOptions, NODE_OPTIONS);
  assert.strictEqual(r.stderr, '');
});

// Cases a review found.

test('NODE_OPTIONS goes whatever path spelling the agent used for the loader', async (t) => {
  const dir = tmp();
  const s = await serve(dir, () => line('SECRET_X', 'v'), t);
  fs.symlinkSync(path.dirname(LOADER), path.join(dir, 'via-link'));
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock },
    { nodeOptions: '--require ' + JSON.stringify(path.join(dir, 'via-link', 'env.cjs')) });
  assert.strictEqual(r.rep.has, 'v', r.stderr);
  assert.strictEqual(r.rep.nodeOptions, undefined);
});

test('a value no environment can hold is refused, and the traces still go', async (t) => {
  const dir = tmp();
  const s = await serve(dir, () => line('SECRET_X', 'a\0b'), t);
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  assert.strictEqual(r.rep.has, undefined);
  assert.deepStrictEqual(r.rep.nazar, []);
  assert.strictEqual(r.rep.nodeOptions, undefined);
  assert.match(r.stderr, /^nazar: secret SECRET_X not delivered: the value can't be an environment variable\n$/);
  // Bytes that are not UTF-8 would silently change: refused too.
  const s2 = await serve(tmp(), () => 'SECRET_X\t' + Buffer.from([0xff, 0xfe]).toString('base64') + '\n', t);
  const r2 = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s2.sock });
  assert.strictEqual(r2.rep.has, undefined);
  assert.match(r2.stderr, /can't be an environment variable/);
});

test("a dependency's own copy of the target package is not the target", async (t) => {
  const dir = tmp();
  project(dir, 'foo');
  const nested = path.join(dir, 'node_modules', 'bar', 'node_modules', 'foo');
  fs.mkdirSync(path.join(nested, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(nested, 'package.json'), JSON.stringify({ name: 'foo', bin: 'dist/cli.js' }));
  fs.writeFileSync(path.join(nested, 'dist', 'cli.js'), PROBE);
  const s = await serve(dir, () => line('SECRET_X', 'x'), t);
  const r = await run(path.join(nested, 'dist', 'cli.js'), { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock, NAZAR_TARGET: 'foo' }, { notRunPid: true });
  assert.strictEqual(r.rep.has, undefined);
  assert.strictEqual(s.conns.length, 0);
});

test('an answer over 256 KiB, and a name the agent did not send, are reported', async (t) => {
  const dir = tmp();
  const s = await serve(dir, () => 'X'.repeat(300 * 1024), t);
  const script = path.join(dir, 'server.js');
  fs.writeFileSync(script, PROBE);
  const r = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X', NAZAR_SECRET_SOCK: s.sock });
  assert.strictEqual(r.rep.has, undefined);
  assert.match(r.stderr, /not delivered: the answer was too long/);
  const s2 = await serve(tmp(), () => line('SECRET_X', 'v'), t);
  const r2 = await run(script, { NAZAR_SECRET_NAMES: 'SECRET_X,SECRET_Y', NAZAR_SECRET_SOCK: s2.sock });
  assert.strictEqual(r2.rep.has, 'v');
  assert.match(r2.stderr, /^nazar: secret SECRET_Y not delivered: nazar-agent did not send it\n$/);
});
