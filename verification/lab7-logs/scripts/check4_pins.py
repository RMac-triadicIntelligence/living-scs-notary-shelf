"""Claim 4: default PINS launch works; one-byte change to a pinned source refused at launch.
Also: show the shipped runners (which pass pins=pins_for(ROOT)) do NOT refuse; supervisor.py unpinned."""
import os, shutil, subprocess, sys, tempfile, hashlib
SRC = "/workspace/lab7/pristine/living_scs_v115"
def scratch():
    d = tempfile.mkdtemp(prefix="lab7_pin_", dir="/workspace/lab7/scratch"); t = os.path.join(d, "living_scs_v115")
    shutil.copytree(SRC, t); return t
def run(root, code):
    p = subprocess.run([sys.executable, "-c", code], cwd=os.path.join(root, "v115"), capture_output=True, text=True, timeout=120)
    return (p.stdout + p.stderr).strip().splitlines()
LAUNCH_DEFAULT = r'''
import sys; sys.path.insert(0,'.'); import os, session, supervisor
ROOT=os.path.dirname(os.path.abspath('.'))
cfg, mat = session.build(ROOT)
try:
    h = supervisor.NotaryHandle(ROOT, cfg, isolation="local")   # pins=None -> supervisor.PINS
    o = supervisor.OrgClient(h.org_w, h.org_r)
    r = o.request({"op":"commit","submission":mat["ISSUED"]})
    print("LAUNCH OK (default PINS); ISSUED ->", r["outcome"], "seq", r["sequence"]); h.shutdown()
except supervisor.PinMismatch as e:
    print("LAUNCH REFUSED PinMismatch:", e)
'''
def flip(path):
    b = bytearray(open(path, "rb").read())
    # change one byte inside a comment/docstring so the code still runs
    i = b.find(b"the only language") if path.endswith("wire.py") else b.find(b"PROPOSE")
    b[i] ^= 0x20; open(path, "wb").write(b)
os.makedirs("/workspace/lab7/scratch", exist_ok=True)
print("== A. pristine tree, default supervisor.PINS")
t = scratch(); print("\n".join(run(t, LAUNCH_DEFAULT)))
for tgt in ["v115/wire.py", "v115/notary.py"]:
    print("== B. one-byte change to %s, default PINS" % tgt)
    t = scratch(); flip(os.path.join(t, tgt)); print("\n".join(run(t, LAUNCH_DEFAULT)))
    print("== C. same tampered tree via shipped runner run_code_attack.py (uses pins_for(ROOT))")
    out = run(t, "import runpy,sys; sys.argv=['run_code_attack.py','attacks/code_03_replay_flood.py']; runpy.run_path('run_code_attack.py', run_name='__main__')")
    print("\n".join(l for l in out if "TARGET STATUS" in l or "PinMismatch" in l or "Traceback" in l))
    print("== C2. same tampered tree via selftest_v115.py")
    out = run(t, "import runpy; runpy.run_path('selftest_v115.py', run_name='__main__')")
    print("\n".join(l for l in out if "HARNESS" in l or "PinMismatch" in l))
print("== D. malicious notary.py + matching edit of supervisor.PINS (supervisor.py unpinned)")
t = scratch(); npath = os.path.join(t, "v115/notary.py")
s = open(npath).read()
s = s.replace('        if op == "head" and set(msg) == {"op"}:',
              '        if op == "grow_up":\n            self.eng._state["maturity"] = "mature"\n            return {"outcome": "ACCEPT", "reason": "backdoor"}\n        if op == "head" and set(msg) == {"op"}:')
open(npath, "w").write(s)
newpin = hashlib.sha256(open(npath, "rb").read()).hexdigest()
sp = os.path.join(t, "v115/supervisor.py"); ss = open(sp).read()
ss = ss.replace("6b854cfabcd8b2e275f5d3d67fa9b71b3fa909eb6cea057ecb45b11536e645d8", newpin); open(sp, "w").write(ss)
print("\n".join(run(t, LAUNCH_DEFAULT.replace('print("LAUNCH OK (default PINS); ISSUED ->"', 'print("LAUNCH OK (default PINS, edited) last reply ->"').replace('r = o.request({"op":"commit","submission":mat["ISSUED"]})',
    'r = o.request({"op":"grow_up"}); print("backdoor op ->", r["outcome"], "maturity now:", h.head()["state"]["maturity"])'))))
print("== E. is supervisor.py in SOURCES/PINS?")
sys.path.insert(0, os.path.join(SRC, "v115")); import supervisor
print("SOURCES keys:", sorted(supervisor.SOURCES), " supervisor.py pinned:", "supervisor.py" in supervisor.PINS)
print("session.py / organism_runner.py pinned:", "session.py" in supervisor.PINS, "organism_runner.py" in supervisor.PINS)
