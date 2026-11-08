# S12 spike: the Python side of the late-env handover. THROWAWAY (spikes/README.md).
# Found through PYTHONPATH=<abs>/python. Writes a report per process to $SPIKE_REPORT_DIR.
def _nazar_spike():
    import os, sys, json, time, hashlib, base64, socket
    env = os.environ
    if not env.get("NAZAR_SECRET_NAMES"):
        return
    rep = {"pid": os.getpid(), "ppid": os.getppid(), "argv": list(getattr(sys, "orig_argv", sys.argv)),
           "executable": sys.executable, "prefix": sys.prefix, "cwd": os.getcwd(), "matched": False,
           "got": {}, "error": "", "t0": time.time()}
    try:
        rep["fd3"] = os.readlink("/proc/self/fd/3")
    except OSError:
        rep["fd3"] = "EBADF"

    def write():
        try:
            with open(os.path.join(env["SPIKE_REPORT_DIR"], "py-%d-%d.json" % (os.getpid(), time.time_ns())), "w") as f:
                json.dump(rep, f)
        except Exception:
            pass

    if str(os.getpid()) == env.get("NAZAR_LAUNCHER_PID"):
        del env["NAZAR_LAUNCHER_PID"]
        rep["skip"] = "launcher pid"
        write()
        return
    target = env.get("NAZAR_TARGET", "")
    script = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    rep["script"] = script
    if target and script != target:
        rep["skip"] = "target"
        write()
        return
    rep["matched"] = True
    data = b""
    try:
        if env.get("NAZAR_SECRET_FD"):
            fd = int(env["NAZAR_SECRET_FD"])
            while True:
                b = os.read(fd, 65536)
                if not b:
                    break
                data += b
            os.close(fd)
        elif env.get("NAZAR_SECRET_SOCK"):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(float(env.get("SPIKE_TIMEOUT_MS", "120000")) / 1000)
            s.connect(env["NAZAR_SECRET_SOCK"])
            while True:
                b = s.recv(65536)
                if not b:
                    break
                data += b
            s.close()
        for line in data.split(b"\n"):
            if not line:
                continue
            name, b64 = line.split(b"\t")
            v = base64.b64decode(b64)
            rep["got"][name.decode()] = hashlib.sha256(v).hexdigest()
            env[name.decode()] = v.decode()
    except Exception as e:
        rep["error"] = repr(e)
    for k in ("NAZAR_SECRET_NAMES", "NAZAR_TARGET", "NAZAR_SECRET_FD", "NAZAR_SECRET_SOCK", "NAZAR_LAUNCHER_PID"):
        env.pop(k, None)
    here = os.path.dirname(os.path.abspath(__file__))
    pp = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and os.path.abspath(p) != here]
    if pp:
        env["PYTHONPATH"] = os.pathsep.join(pp)
    else:
        env.pop("PYTHONPATH", None)
    rep["t1"] = time.time()
    write()


_nazar_spike()
del _nazar_spike

# Hand over to the next sitecustomize on sys.path (a venv's or the distro's).
import sys as _sys, os as _os, importlib as _il
_here = _os.path.dirname(_os.path.abspath(__file__))
_sys.path[:] = [p for p in _sys.path if _os.path.abspath(p or ".") != _here]
del _sys.modules["sitecustomize"]
try:
    _il.import_module("sitecustomize")
except ImportError:
    pass
