import os, sys, json, hashlib, time
def main():
    v = os.environ.get("SPIKE_SECRET")
    rep = {"pid": os.getpid(), "has": v is not None, "hash": hashlib.sha256(v.encode()).hexdigest() if v else "",
           "cwd": os.getcwd(), "argv0": sys.argv[0], "executable": sys.executable,
           "nazarLeft": [k for k in os.environ if k.startswith("NAZAR_")], "pythonpath": os.environ.get("PYTHONPATH", ""),
           "fds": sorted(os.listdir("/proc/self/fd"), key=int)}
    with open(os.path.join(os.environ["SPIKE_REPORT_DIR"], "target-%d.json" % os.getpid()), "w") as f:
        json.dump(rep, f)
    if os.environ.get("SPIKE_STAY"):
        while True:
            time.sleep(1)
