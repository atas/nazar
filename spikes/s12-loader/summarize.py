#!/usr/bin/env python3
"""Condense run.py's JSON lines into one row per scenario (THROWAWAY)."""
import json, sys
for l in sys.stdin:
    try:
        d = json.loads(l)
    except Exception:
        print("!!", l.rstrip()); continue
    t = d.get("target") or {}
    ld = [(x["pid"], x.get("skip") or ("MATCH got=%s err=%s" % (list(x.get("got", {})), x.get("error"))), (x.get("mainReal") or (x.get("argv") or [""])[-1])[-70:]) for x in d["loaders"]]
    print("== %s  elapsed=%ss targetGotValue=%s valueInAnyEnviron=%s launcherCwd(serve/end)=%s/%s exit=%s" % (
        d["scenario"], d["elapsed"], d["targetGotValue"], d["valueInAnyEnviron"], d["launcherCwdAtServe"], d["launcherCwdAtEnd"], d["exitCode"]))
    if t:
        print("   target pid=%s has=%s cwd=%s nazarLeft=%s fd3=%s nodeOptions=%r pythonpath=%r" % (t.get("pid"), t.get("has"), t.get("cwd"), t.get("nazarLeft"),
              [f for f in t.get("fds", []) if str(f).startswith("3")], t.get("nodeOptions"), t.get("pythonpath")))
    for x in ld:
        print("   loader", x)
    for x in d.get("socketLog") or []:
        print("   socket peer pid=%s accepted=%s argv=%s" % (x["pid"], x["accepted"], " ".join(x["argv"] or [])[-90:]))
    for x in d["tree"]:
        print("   tree %s %-40s cwd=%s valueInEnviron=%s nazar=%s" % (x["pid"], " ".join(x["argv"] or [])[-80:], x["cwd"], x["valueInEnviron"], x["nazarVars"]))
    if not d["targetGotValue"]:
        print("   stderr:", d["stderrTail"][-400:].replace("\n", " | "))
