#!/usr/bin/env python3
"""S12 spike driver (THROWAWAY, spikes/README.md). Linux only: it reads /proc.

For each launcher scenario it plays nazar-agent and the `nazar run` CLI:
  - builds an allowlisted environment (PATH = a trusted path, HOME, USER, LOGNAME, LANG)
    plus the loader variables, and starts the command in `/` (or another directory);
  - `fd` handover: a pipe whose read end is the child's fd 3, written after the exec;
  - `socket` handover: a per-run unix socket in a 0700 directory, served to exactly one
    peer that is the exec'd pid or a descendant of it (SO_PEERCRED + /proc ppid walk);
    a rejected peer does not consume the accept. In socket scenarios an unrelated pipe
    is planted at fd 3 to measure question (a): does an inherited fd 3 reach the target;
  - waits for the target's own report, then snapshots every process of the tree:
    does any /proc/<pid>/environ hold the value, does any hold NAZAR_* variables.

Usage: run.py <scenario>... | all ; prints one JSON object per scenario.
"""
import base64, hashlib, json, os, secrets, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRATCH = os.environ.get("SPIKE_SCRATCH") or tempfile.mkdtemp(prefix="s12-")
NODE_BIN = os.environ.get("SPIKE_NODE_BIN", "/opt/node22/bin")
NODE20 = "/opt/node20/bin"
NODE24 = os.environ.get("SPIKE_NODE24_BIN", "")
TRUSTED = [NODE_BIN, os.path.expanduser("~/.local/bin"), os.path.expanduser("~/.bun/bin"), "/usr/local/bin", "/usr/bin", "/bin"]


def ppid_of(pid):
    with open("/proc/%d/stat" % pid) as f:
        s = f.read()
    return int(s[s.rindex(")") + 2:].split()[1])


def chain(pid):
    out = []
    while pid > 1:
        out.append(pid)
        try:
            pid = ppid_of(pid)
        except OSError:
            break
    return out


def cmdline(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            b = f.read()
            return [a.decode("utf-8", "replace") for a in (b[:-1] if b.endswith(b"\0") else b).split(b"\0")] if b else []
    except OSError:
        return None


def readlink(p):
    try:
        return os.readlink(p)
    except OSError as e:
        return "ERR:%s" % e.strerror


def descendants(root):
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            pid = int(d)
            if root in chain(pid):
                out.append(pid)
    return sorted(out)


class Server(threading.Thread):
    def __init__(self, path, launcher, payload):
        super().__init__(daemon=True)
        self.path, self.launcher, self.payload = path, launcher, payload
        self.log, self.served, self.launcher_cwd_at_serve = [], None, None
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.bind(path)
        os.chmod(path, 0o600)
        self.s.listen(8)
        self.s.settimeout(0.2)
        self.stop = False

    def run(self):
        while not self.stop and self.served is None:
            try:
                c, _ = self.s.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            cred = c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", cred)
            launcher = self.launcher()
            ok = launcher is not None and launcher in chain(pid)
            self.log.append({"pid": pid, "argv": cmdline(pid), "accepted": ok, "chainHasLauncher": ok,
                             "launcherCwd": readlink("/proc/%d/cwd" % launcher) if launcher else None})
            if ok:
                self.launcher_cwd_at_serve = readlink("/proc/%d/cwd" % launcher)
                c.sendall(self.payload)
                self.served = pid
            c.close()
        try:
            self.s.close()
            os.unlink(self.path)
        except OSError:
            pass


def scenario(name, argv, *, mode, target="", cwd="/", timeout=180, extra_env=None, plant_fd3=True, via="require", launcher=True, secret="SPIKE_SECRET"):
    work = tempfile.mkdtemp(prefix=name + "-", dir=SCRATCH)
    reports = os.path.join(work, "reports")
    os.mkdir(reports)
    value = "s12-" + secrets.token_hex(16)
    want = hashlib.sha256(value.encode()).hexdigest()
    payload = secret.encode() + b"\t" + base64.b64encode(value.encode()) + b"\n"
    home = os.path.expanduser("~")
    env = {"PATH": ":".join(TRUSTED), "HOME": home, "USER": "root", "LOGNAME": "root", "LANG": "C.UTF-8",
           "NAZAR_SECRET_NAMES": secret, "SPIKE_REPORT_DIR": reports, "SPIKE_STAY": "1", "SPIKE_VIA": via}
    if via == "require":
        env["NODE_OPTIONS"] = "--require " + os.path.join(HERE, "loader.cjs")
    elif via == "import":
        env["NODE_OPTIONS"] = "--import " + "file://" + os.path.join(HERE, "loader.mjs")
    env["PYTHONPATH"] = os.path.join(HERE, "python")
    if target:
        env["NAZAR_TARGET"] = target
    # A network may require a proxy and its CA, set through these variables; nazar's allowlist
    # would drop them (the deny set), so the spike passes them explicitly.
    for k in ("HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "UV_NATIVE_TLS", "npm_config_https_proxy", "PIP_CERT", "REQUESTS_CA_BUNDLE"):
        if os.environ.get(k) and os.environ.get("SPIKE_NETWORK_ENV", "1") == "1":
            env[k] = os.environ[k]
    env.update(extra_env or {})
    sockdir = None
    r = w = None
    if mode == "socket":
        sockdir = tempfile.mkdtemp(prefix="s12-run-", dir="/tmp")  # sun_path is 108 bytes on Linux, 104 on macOS
        os.chmod(sockdir, 0o700)
        env["NAZAR_SECRET_SOCK"] = os.path.join(sockdir, secrets.token_hex(16) + ".sock")
    else:
        env["NAZAR_SECRET_FD"] = "3"
    r, w = os.pipe()
    os.set_inheritable(r, True)
    holder = {}
    srv = None
    if mode == "socket":
        srv = Server(env["NAZAR_SECRET_SOCK"], lambda: holder.get("pid"), payload)
        srv.start()

    def pre():
        os.chdir(cwd)
        if mode == "fd" or plant_fd3:
            os.dup2(r, 3)
        os.umask(0o022)

    # `sh -c 'NAZAR_LAUNCHER_PID=$$ exec …'`: the pid the CLI would have had (it execs in place).
    full = (["/bin/sh", "-c", 'export NAZAR_LAUNCHER_PID=$$; exec "$@"', "sh"] if launcher else []) + argv
    t0 = time.time()
    p = subprocess.Popen(full, env=env, stdin=subprocess.PIPE, stdout=open(os.path.join(work, "stdout"), "wb"),
                         stderr=open(os.path.join(work, "stderr"), "wb"), preexec_fn=pre, pass_fds=(r,), start_new_session=True)
    holder["pid"] = p.pid
    os.close(r)
    if mode == "fd":
        time.sleep(0.05)  # stands in for "after NOTE_EXEC"
        os.write(w, payload)
    os.close(w)
    target_rep = None
    deadline = t0 + timeout
    while time.time() < deadline and target_rep is None:
        for f in os.listdir(reports):
            if f.startswith("target-"):
                time.sleep(0.2)
                with open(os.path.join(reports, f)) as fh:
                    target_rep = json.load(fh)
        got = [f for f in os.listdir(reports) if not f.startswith("target-")]
        if target_rep is None and any(json.load(open(os.path.join(reports, f))).get("matched") for f in got):
            time.sleep(2)  # a public package writes no target report: the loader's is enough
            break
        if p.poll() is not None and target_rep is None:
            time.sleep(0.5)
            break
        time.sleep(0.1)
    elapsed = round(time.time() - t0, 2)
    tree = []
    for pid in descendants(p.pid):
        try:
            with open("/proc/%d/environ" % pid, "rb") as f:
                envb = f.read()
        except OSError:
            envb = b""
        tree.append({"pid": pid, "argv": cmdline(pid), "exe": readlink("/proc/%d/exe" % pid), "cwd": readlink("/proc/%d/cwd" % pid),
                     "valueInEnviron": value.encode() in envb,
                     "nazarVars": sorted(set(k.split(b"=")[0].decode() for k in envb.split(b"\0") if k.startswith(b"NAZAR_")))})
    launcher_cwd_now = readlink("/proc/%d/cwd" % p.pid)
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    p.wait()
    if srv:
        srv.stop = True
        srv.join(2)
    loaders = []
    for f in sorted(os.listdir(reports)):
        if not f.startswith("target-"):
            with open(os.path.join(reports, f)) as fh:
                loaders.append(json.load(fh))
    out = {"scenario": name, "argv": argv, "mode": mode, "cwd": cwd, "via": via, "elapsed": elapsed,
           "targetGotValue": bool(target_rep and target_rep.get("has") and target_rep.get("hash") == want),
           "target": target_rep, "loaders": loaders, "socketLog": srv.log if srv else None,
           "launcherCwdAtServe": srv.launcher_cwd_at_serve if srv else None, "launcherCwdAtEnd": launcher_cwd_now,
           "valueInAnyEnviron": any(t["valueInEnviron"] for t in tree), "tree": tree,
           "exitCode": p.returncode, "stderrTail": open(os.path.join(work, "stderr"), "rb").read()[-600:].decode("utf-8", "replace")}
    return out


def setup():
    """Pack the local test packages once, into the scratch directory."""
    pk = os.path.join(SCRATCH, "pkgs")
    if os.path.isdir(pk):
        return pk
    shutil.copytree(os.path.join(HERE, "pkgs"), pk)
    npm = os.path.join(NODE_BIN, "npm")
    subprocess.run([npm, "pack", "--silent", "--pack-destination", pk], cwd=os.path.join(pk, "node-post"), check=True, stdout=subprocess.DEVNULL)
    pj = os.path.join(pk, "node-cjs", "package.json")
    d = json.load(open(pj))
    d["dependencies"]["s12-post"] = "file:" + os.path.join(pk, "s12-post-1.0.0.tgz")
    json.dump(d, open(pj, "w"))
    for n in ("node-cjs", "node-esm"):
        subprocess.run([npm, "pack", "--silent", "--pack-destination", pk], cwd=os.path.join(pk, n), check=True, stdout=subprocess.DEVNULL)
    return pk


def planted(pk):
    """A caller directory with a planted node_modules/s12-cjs whose bin writes a marker, and an
    .npmrc with script-shell and registry (6.3.7). The scenario run from `/` must ignore it."""
    d = os.path.join(pk, "planted")
    if not os.path.isdir(d):
        os.makedirs(os.path.join(d, "node_modules", "s12-cjs"))
        os.makedirs(os.path.join(d, "node_modules", ".bin"))
        with open(os.path.join(d, "node_modules", "s12-cjs", "package.json"), "w") as f:
            json.dump({"name": "s12-cjs", "version": "6.6.6", "bin": {"s12-cjs": "evil.js"}}, f)
        with open(os.path.join(d, "node_modules", "s12-cjs", "evil.js"), "w") as f:
            f.write("#!/usr/bin/env node\nrequire('fs').writeFileSync(process.env.SPIKE_REPORT_DIR + '/target-evil-' + process.pid + '.json', JSON.stringify({pid: process.pid, has: 'SPIKE_SECRET' in process.env, evil: true, cwd: process.cwd()}));\n")
        os.chmod(os.path.join(d, "node_modules", "s12-cjs", "evil.js"), 0o755)
        os.symlink("../s12-cjs/evil.js", os.path.join(d, "node_modules", ".bin", "s12-cjs"))
        with open(os.path.join(d, ".npmrc"), "w") as f:
            f.write("script-shell=%s/x.sh\nregistry=http://127.0.0.1:1/\n" % d)
        with open(os.path.join(d, "x.sh"), "w") as f:
            f.write("#!/bin/sh\necho planted-shell > \"$SPIKE_REPORT_DIR/planted-shell-marker\"\nexec /bin/sh \"$@\"\n")
        os.chmod(os.path.join(d, "x.sh"), 0o755)
    return d


def scenarios():
    pk = setup()
    cjs, esm, py = os.path.join(pk, "s12-cjs-1.0.0.tgz"), os.path.join(pk, "s12-esm-1.0.0.tgz"), os.path.join(pk, "py")
    npx = os.path.join(NODE_BIN, "npx")
    return {
        "npx-cjs-socket": lambda: scenario("npx-cjs-socket", [npx, "-y", "--package=" + cjs, "s12-cjs"], mode="socket", target="s12-cjs"),
        "npx-cjs-socket-notarget": lambda: scenario("npx-cjs-socket-notarget", [npx, "-y", "--package=" + cjs, "s12-cjs"], mode="socket"),
        "npx-esm-socket": lambda: scenario("npx-esm-socket", [npx, "-y", "--package=" + esm, "s12-esm"], mode="socket", target="s12-esm"),
        "npx-esm-import": lambda: scenario("npx-esm-import", [npx, "-y", "--package=" + esm, "s12-esm"], mode="socket", target="s12-esm", via="import"),
        "npx-cjs-fd": lambda: scenario("npx-cjs-fd", [npx, "-y", "--package=" + cjs, "s12-cjs"], mode="fd", target="s12-cjs"),
        "node-direct-fd": lambda: scenario("node-direct-fd", [os.path.join(NODE_BIN, "node"), os.path.join(pk, "node-cjs", "bin.js")], mode="fd", launcher=False),
        "npx-brave-socket": lambda: scenario("npx-brave-socket", [npx, "-y", "@brave/brave-search-mcp-server"], mode="socket", target="@brave/brave-search-mcp-server", secret="BRAVE_API_KEY"),
        "npx-brave-socket-node24": lambda: scenario("npx-brave-socket-node24", [os.path.join(NODE24, "npx"), "-y", "@brave/brave-search-mcp-server"], mode="socket", target="@brave/brave-search-mcp-server", secret="BRAVE_API_KEY", extra_env={"PATH": ":".join([NODE24] + TRUSTED[1:])}),
        "npx-esm-socket-node20": lambda: scenario("npx-esm-socket-node20", [os.path.join(NODE20, "npx"), "-y", "--package=" + esm, "s12-esm"], mode="socket", target="s12-esm", extra_env={"PATH": ":".join([NODE20] + TRUSTED[1:])}),
        "npx-esm-import-node20": lambda: scenario("npx-esm-import-node20", [os.path.join(NODE20, "npx"), "-y", "--package=" + esm, "s12-esm"], mode="socket", target="s12-esm", via="import", extra_env={"PATH": ":".join([NODE20] + TRUSTED[1:])}),
        "npx-esm-socket-node24": lambda: scenario("npx-esm-socket-node24", [os.path.join(NODE24, "npx"), "-y", "--package=" + esm, "s12-esm"], mode="socket", target="s12-esm", extra_env={"PATH": ":".join([NODE24] + TRUSTED[1:])}),
        "bun-direct-fd": lambda: scenario("bun-direct-fd", [os.path.expanduser("~/.bun/bin/bun"), os.path.join(pk, "node-cjs", "bin.js")], mode="fd", launcher=False),
        "bunx-bun-cjs-socket": lambda: scenario("bunx-bun-cjs-socket", ["bunx", "--bun", "--package=" + cjs, "s12-cjs"], mode="socket", target="s12-cjs"),
        "npx-planted-at-root": lambda: (planted(pk), scenario("npx-planted-at-root", [npx, "-y", "s12-cjs"], mode="socket", target="s12-cjs", timeout=60))[1],
        "npx-planted-in-caller-dir": lambda: scenario("npx-planted-in-caller-dir", [npx, "-y", "s12-cjs"], mode="socket", target="s12-cjs", cwd=planted(pk), timeout=30),
        "pnpm-dlx-cjs-socket": lambda: scenario("pnpm-dlx-cjs-socket", ["pnpm", "--package=" + cjs, "dlx", "s12-cjs"], mode="socket", target="s12-cjs"),
        "bunx-cjs-socket": lambda: scenario("bunx-cjs-socket", ["bunx", "--package=" + cjs, "s12-cjs"], mode="socket", target="s12-cjs"),
        "uvx-py-socket": lambda: scenario("uvx-py-socket", ["uvx", "--from", py, "s12-py"], mode="socket", target="s12-py"),
        "uvx-py-fd": lambda: scenario("uvx-py-fd", ["uvx", "--from", py, "s12-py"], mode="fd", target="s12-py"),
        "pipx-py-socket": lambda: scenario("pipx-py-socket", ["pipx", "run", "--spec", py, "s12-py"], mode="socket", target="s12-py"),
        "uv-run-py-socket": lambda: scenario("uv-run-py-socket", ["uv", "run", "--project", py, "s12-py"], mode="socket", target="s12-py"),
        "python-direct-fd": lambda: scenario("python-direct-fd", ["/usr/bin/python3", "-c", "import sys; sys.path.insert(0, %r); import s12py; s12py.main()" % py], mode="fd", launcher=False),
        "uvx-pycowsay-socket": lambda: scenario("uvx-pycowsay-socket", ["uvx", "pycowsay", "hi"], mode="socket", target="pycowsay"),
        "pipx-pycowsay-socket": lambda: scenario("pipx-pycowsay-socket", ["pipx", "run", "pycowsay", "hi"], mode="socket", target="pycowsay"),
    }


if __name__ == "__main__":
    allsc = scenarios()
    names = list(allsc) if sys.argv[1:] == ["all"] else sys.argv[1:]
    for n in names:
        print(json.dumps(allsc[n]()), flush=True)
