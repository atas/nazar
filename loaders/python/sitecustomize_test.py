"""Tests of loaders/python/sitecustomize.py.

Run: python3 -m unittest discover -s loaders/python -p '*_test.py'

Each test starts a real python3 with PYTHONPATH=<loader dir>, as nazar-agent
does, through `sh -c 'NAZAR_RUN_PID=$$; exec python3 …'` (the pid the CLI
exec'd in), and plays the agent on a real unix socket.
"""

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

LOADER_DIR = os.path.dirname(os.path.abspath(__file__))

PROBE = r"""
import json, os, sys
v = os.environ.get("SECRET_X")
with open(os.environ["REPORT"], "w") as f:
    json.dump({"has": v, "nazar": sorted(k for k in os.environ if k.startswith("NAZAR_")),
               "pythonpath": os.environ.get("PYTHONPATH"), "injected": os.environ.get("INJECTED"),
               "loaderOnPath": %r in [os.path.abspath(p or ".") for p in sys.path],
               "chained": os.environ.get("CHAINED_MARKER"),
               "bytecodeVar": os.environ.get("PYTHONDONTWRITEBYTECODE"),
               "dontWrite": sys.dont_write_bytecode}, f)
""" % LOADER_DIR


def line(name, value):
    return name.encode() + b"\t" + base64.b64encode(value.encode()) + b"\n"


class Server:
    """A unix socket that answers every connection with `answer` (None:
    close at once) and counts connections; `before`, if given, runs after
    the accept and before the answer (where the agent's last check is)."""

    def __init__(self, d, answer, before=None):
        self.path = os.path.join(d, "s.sock")
        self.answer = answer
        self.before = before
        self.conns = 0
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.bind(self.path)
        self.s.listen(4)
        self.s.settimeout(0.2)
        self.stop = False
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        while not self.stop:
            try:
                c, _ = self.s.accept()
            except socket.timeout:
                continue
            self.conns += 1
            if self.before is not None:
                self.before()
            if self.answer is not None:
                c.sendall(self.answer)
            c.close()

    def close(self):
        self.stop = True
        self.t.join(2)
        self.s.close()


class Harness(unittest.TestCase):
    """Real python3 processes against a real socket."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="nzp-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.script = os.path.join(self.d, "app.py")
        with open(self.script, "w") as f:
            f.write(PROBE)
        self.report = os.path.join(self.d, "report.json")

    def run_py(self, env, not_run_pid=False, flags=(), pythonpath=None, no_stderr=False):
        full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.path.expanduser("~"),
                "PYTHONPATH": pythonpath or LOADER_DIR, "REPORT": self.report, "PYTHONDONTWRITEBYTECODE": "1"}
        full.update(env)
        pid = "NAZAR_RUN_PID=1" if not_run_pid else "NAZAR_RUN_PID=$$"
        if os.path.exists(self.report):
            os.unlink(self.report)  # never read an earlier run's report
        close = " 2>&-" if no_stderr else ""
        p = subprocess.run(["/bin/sh", "-c", 'export %s; exec "$@"%s' % (pid, close), "sh", sys.executable, *flags, self.script],
                           env=full, cwd="/", capture_output=True, timeout=60)
        rep = None
        if os.path.exists(self.report):
            with open(self.report) as f:
                rep = json.load(f)
        return rep, p.stderr.decode(), p.returncode

    def serve(self, answer, before=None):
        s = Server(self.d, answer, before)
        self.addCleanup(s.close)
        return s


class LoaderTest(Harness):
    def test_exec_d_process_gets_the_value_before_main(self):
        s = self.serve(line("SECRET_X", "v4lue with spaces\nand a newline"))
        rep, err, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path})
        self.assertEqual(code, 0, err)
        self.assertEqual(rep["has"], "v4lue with spaces\nand a newline")
        self.assertEqual(rep["nazar"], [])
        self.assertIsNone(rep["pythonpath"])
        self.assertFalse(rep["loaderOnPath"])
        self.assertEqual(s.conns, 1)
        self.assertEqual(err, "")

    def test_another_process_does_nothing(self):
        s = self.serve(line("SECRET_X", "no"))
        rep, err, _ = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path}, not_run_pid=True)
        self.assertIsNone(rep["has"])
        self.assertEqual(s.conns, 0)
        self.assertEqual(rep["nazar"], ["NAZAR_RUN_PID", "NAZAR_SECRET_NAMES", "NAZAR_SECRET_SOCK"])

    def test_a_python_launcher_run_is_left_alone(self):
        s = self.serve(line("SECRET_X", "no"))
        rep, _, _ = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path, "NAZAR_TARGET": "x"})
        self.assertIsNone(rep["has"])
        self.assertEqual(s.conns, 0)

    def test_only_the_names_asked_for_each_once(self):
        s = self.serve(line("INJECTED", "x") + line("PYTHONPATH", "/tmp/evil") + line("SECRET_X", "one")
                       + line("SECRET_X", "two") + b"SECRET_X\t%%%\n")
        rep, _, _ = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path})
        self.assertEqual(rep["has"], "one")
        self.assertIsNone(rep["injected"])
        self.assertIsNone(rep["pythonpath"])

    def test_refusal_is_one_line_and_the_program_starts(self):
        s = self.serve(None)
        rep, err, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path})
        self.assertEqual(code, 0)
        self.assertIsNone(rep["has"])
        self.assertEqual(rep["nazar"], [])
        self.assertEqual(err, "nazar: secret SECRET_X not delivered: nazar-agent refused or closed the connection\n")
        rep, err, _ = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": os.path.join(self.d, "gone.sock")})
        self.assertIsNone(rep["has"])
        self.assertIn("not delivered: nazar-agent is not handing it over", err)

    def test_the_next_sitecustomize_still_runs(self):
        other = os.path.join(self.d, "venvsite")
        os.mkdir(other)
        with open(os.path.join(other, "sitecustomize.py"), "w") as f:
            f.write("import os\nos.environ['CHAINED_MARKER'] = 'ran'\n")
        s = self.serve(line("SECRET_X", "v"))
        rep, err, _ = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path},
                                  pythonpath=LOADER_DIR + os.pathsep + other)
        self.assertEqual(rep["has"], "v", err)
        self.assertEqual(rep["chained"], "ran")
        self.assertEqual(rep["pythonpath"], other)

    def test_flags_that_skip_the_loader(self):
        # Why nazar run refuses -I, -E and -S: the loader never runs.
        s = self.serve(line("SECRET_X", "v"))
        for flag in ("-I", "-E", "-S"):
            rep, _, _ = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path}, flags=(flag,))
            self.assertIsNone(rep["has"], flag)
        self.assertEqual(s.conns, 0)

    def test_the_bytecode_switch_goes_with_the_other_traces(self):
        # nazar-agent sets PYTHONDONTWRITEBYTECODE=1 so Python writes
        # no __pycache__ beside the loader, inside the signed bundle. The
        # receiver keeps the setting; the processes it starts do not get it.
        s = self.serve(line("SECRET_X", "v"))
        rep, err, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path})
        self.assertEqual(code, 0, err)
        self.assertEqual(rep["has"], "v")
        self.assertIsNone(rep["bytecodeVar"])
        self.assertTrue(rep["dontWrite"])

    def test_the_loader_folder_is_left_as_it_was(self):
        # nazar-agent pins the loader's folder: a run with its
        # variables adds nothing there and changes nothing.
        d = os.path.join(self.d, "loaders", "python")
        os.makedirs(d)
        shutil.copy(os.path.join(LOADER_DIR, "sitecustomize.py"), d)
        st = os.stat(d)
        before = (sorted(os.listdir(d)), st.st_mtime_ns, st.st_ctime_ns)
        s = self.serve(line("SECRET_X", "v"))
        rep, err, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path}, pythonpath=d)
        self.assertEqual(code, 0, err)
        self.assertEqual(rep["has"], "v")
        st = os.stat(d)
        self.assertEqual((sorted(os.listdir(d)), st.st_mtime_ns, st.st_ctime_ns), before)

    def test_a_module_added_beside_the_loader_after_the_last_check_never_runs(self):
        # nazar-agent checks the loader's folder for the last time right
        # before it writes. A module dropped there after that check
        # must not be imported: the loader leaves its folder before any
        # import of its own.
        d = os.path.join(self.d, "loaders", "python")
        os.makedirs(d)
        shutil.copy(os.path.join(LOADER_DIR, "sitecustomize.py"), d)
        marker = os.path.join(self.d, "planted")
        mods = ("base64", "binascii", "importlib", "time", "socket", "selectors", "enum")

        def plant():
            for m in mods:
                with open(os.path.join(d, m + ".py"), "w") as f:
                    f.write("open(%r, 'a').write(%r)\nraise ImportError('planted')\n" % (marker, m + "\n"))

        s = self.serve(line("SECRET_X", "v"), before=plant)
        rep, err, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path}, pythonpath=d)
        self.assertEqual(s.conns, 1)
        if os.path.exists(marker):
            with open(marker) as f:
                self.fail("imported from the loader's folder: " + f.read())
        self.assertEqual(code, 0, err)
        self.assertEqual(rep["has"], "v")
        self.assertFalse(rep["loaderOnPath"])
        self.assertEqual(err, "")

    def test_without_the_variables_nothing_happens(self):
        rep, err, _ = self.run_py({})
        self.assertIsNone(rep["has"])
        self.assertEqual(err, "")
        self.assertEqual(rep["pythonpath"], LOADER_DIR)


class ReviewTest(Harness):
    """Cases a review found."""

    def test_no_other_sitecustomize(self):
        # The usual case on a Mac (mise, Homebrew, python.org ship none):
        # hide every other sitecustomize and import the loader as site would.
        harness = (
            "import sys, importlib.abc\n"
            "class Hide(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name == 'sitecustomize' and %r not in [p for p in sys.path]:\n"
            "            raise ImportError('hidden', name='sitecustomize')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Hide())\n"
            "sys.path.insert(0, %r)\n"
            "import sitecustomize\n"
            "print('started')\n"
        ) % (LOADER_DIR, LOADER_DIR)
        p = subprocess.run([sys.executable, "-S", "-c", harness], capture_output=True, timeout=60,
                           env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.decode(), "started\n")
        self.assertEqual(p.stderr.decode(), "")

    def test_stderr_closed(self):
        s = self.serve(None)
        rep, _, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path}, no_stderr=True)
        self.assertEqual(code, 0)
        self.assertIsNotNone(rep, "the program must start")
        self.assertEqual(rep["nazar"], [])

    def test_a_value_no_environment_can_hold(self):
        s = self.serve(line("SECRET_X", "a\0b"))
        rep, err, code = self.run_py({"NAZAR_SECRET_NAMES": "SECRET_X", "NAZAR_SECRET_SOCK": s.path})
        self.assertEqual(code, 0)
        self.assertIsNone(rep["has"])
        self.assertEqual(rep["nazar"], [])
        self.assertIsNone(rep["pythonpath"])
        self.assertEqual(err, "nazar: secret SECRET_X not delivered: the value can't be an environment variable\n")


if __name__ == "__main__":
    unittest.main()
