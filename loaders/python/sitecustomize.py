# nazar's Python loader (secrets design 6.3.1; 6.3 D1). nazar-agent
# starts a `nazar run` Python receiver with PYTHONPATH=<this directory>, so
# `site` imports this file before __main__, and with these variables, none
# of which holds a secret:
#
#   NAZAR_SECRET_NAMES  the variables to set, comma-separated
#   NAZAR_SECRET_SOCK   the per-run unix socket the agent serves them on
#   NAZAR_RUN_PID       the pid `nazar run` exec'd in
#   PYTHONDONTWRITEBYTECODE  set by nazar-agent so Python writes no
#                       __pycache__ here, inside the signed bundle; removed
#                       with the rest, so the receiver's children write
#                       bytecode as usual
#
# The exec'd process reads `NAME\tbase64(value)\n` lines from the socket,
# sets them in os.environ (which also putenv()s, so C extensions see them),
# and removes every trace of nazar from its environment and sys.path, so
# the processes it starts never run this file again. Any other process
# leaves everything as it is. Python launchers (NAZAR_TARGET) are not in
# this version: such a run is left alone. A failure is one line on stderr,
# never the value, and the program starts without the variable. Then the
# next sitecustomize on sys.path (a venv's, the distribution's) runs.
#
# First of all, before any import, the loader takes its own folder off
# sys.path: nazar-agent checks that folder for the last time before it
# writes, so a module put there later (a base64.py, an importlib.py) must
# never be imported. `os` and `sys` are loaded before site runs this file.


def _nazar_leave_folder():
    import os
    import sys

    here = os.path.dirname(os.path.abspath(__file__))
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != here]
    return here


_nazar_here = _nazar_leave_folder()  # if this fails, nothing below runs
del _nazar_leave_folder


def _nazar_late_env(here):
    import os

    env = os.environ
    names = [n for n in env.get("NAZAR_SECRET_NAMES", "").split(",") if n]
    sock = env.get("NAZAR_SECRET_SOCK", "")
    if not names or not sock or env.get("NAZAR_TARGET") or env.get("NAZAR_RUN_PID") != str(os.getpid()):
        return
    import sys

    reasons = {}
    try:
        data, reason = _nazar_read(sock)
        for line in data.split(b"\n"):
            name, sep, b64 = line.partition(b"\t")
            try:
                name = name.decode("ascii")
            except UnicodeDecodeError:
                continue
            if not sep or name not in names or name in reasons:
                continue
            import base64
            import binascii

            try:
                value = base64.b64decode(b64, validate=True)
            except (binascii.Error, ValueError):
                continue
            if b"\0" in value:
                reasons[name] = "the value can't be an environment variable"
                continue
            env[name] = value.decode("utf-8", "surrogateescape")
            reasons[name] = ""
        for n in names:
            reasons.setdefault(n, reason or "nazar-agent did not send it")
    except Exception:
        for n in names:
            reasons.setdefault(n, "the loader failed")
    finally:
        for k in ("NAZAR_SECRET_NAMES", "NAZAR_SECRET_SOCK", "NAZAR_RUN_PID", "NAZAR_TARGET", "PYTHONDONTWRITEBYTECODE"):
            env.pop(k, None)
        rest = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and os.path.abspath(p) != here]
        if rest:
            env["PYTHONPATH"] = os.pathsep.join(rest)
        else:
            env.pop("PYTHONPATH", None)
    for n in names:
        if reasons[n] and sys.stderr is not None:
            try:
                sys.stderr.write("nazar: secret %s not delivered: %s\n" % (n, reasons[n]))
            except Exception:
                pass


def _nazar_read(path):
    # The answer on the per-run socket, read to its end within one overall
    # deadline (past the agent's own 120 s), and why there is none.
    import socket
    import time

    deadline = time.monotonic() + 130
    data = b""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(max(deadline - time.monotonic(), 0.001))
        s.connect(path)
        while len(data) <= 256 * 1024:
            s.settimeout(max(deadline - time.monotonic(), 0.001))
            b = s.recv(65536)
            if not b:
                break
            data += b
    except (FileNotFoundError, ConnectionRefusedError):
        return b"", "nazar-agent is not handing it over (no socket)"
    except socket.timeout:
        return b"", "nazar-agent did not answer"
    except OSError:
        return b"", "nazar-agent refused or closed the connection"
    finally:
        s.close()
    if len(data) > 256 * 1024:
        return b"", "the answer was too long"
    if not data:
        return b"", "nazar-agent refused or closed the connection"
    return data, ""


try:
    _nazar_late_env(_nazar_here)
except Exception:  # the receiver starts whatever happens here
    pass
del _nazar_late_env, _nazar_read


def _nazar_hand_over():
    # Hand over to the next sitecustomize on sys.path (this folder is off it
    # already), so a virtualenv's or the distribution's still runs (6.3.1
    # step 4), and report an error inside it as site would.
    import importlib
    import sys

    me = sys.modules.pop("sitecustomize", None)
    try:
        importlib.import_module("sitecustomize")
    except ImportError as e:
        if e.name != "sitecustomize":
            raise
        if me is not None:
            sys.modules["sitecustomize"] = me


_nazar_hand_over()
del _nazar_hand_over, _nazar_here
