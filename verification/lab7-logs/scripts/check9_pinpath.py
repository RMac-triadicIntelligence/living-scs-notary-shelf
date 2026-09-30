"""Review finding: the shipped runners pass pins=pins_for(ROOT), which RECOMPUTES the
pins from whatever is on disk -> the launch-time pin gate becomes a no-op. Only the
default (pins=None -> supervisor.PINS) actually detects a changed source.
We prove it on a tampered notary.py in a scratch copy (originals untouched)."""
import os, shutil, sys, tempfile, hashlib
SRC = "/workspace/lab7/pristine/living_scs_v115"
d = tempfile.mkdtemp(prefix="lab7_pinpath_", dir="/tmp"); root = os.path.join(d, "living_scs_v115")
shutil.copytree(SRC, root)
np = os.path.join(root, "v115", "notary.py")
s = open(np).read().replace('SUB_KEYS = {"proposal", "trace", "auth", "artifact", "reason"}',
                            'SUB_KEYS = {"proposal", "trace", "auth", "artifact", "reason"}  # TAMPERED')
open(np, "w").write(s)
got = hashlib.sha256(open(np,"rb").read()).hexdigest()
sys.path.insert(0, os.path.join(root, "v115"))
import supervisor, session
print("notary.py on disk :", got[:12], "  supervisor.PINS   :", supervisor.PINS["notary.py"][:12], "  match:", got==supervisor.PINS["notary.py"])
cfg, mat = session.build(root)
print("\n[1] pins=supervisor.pins_for(ROOT)  (what run_code_attack/selftest/lane_code/run_corpus_oop pass):")
try:
    h = supervisor.NotaryHandle(root, cfg, isolation="local", pins=supervisor.pins_for(root))
    print("    LAUNCHED tampered notary.py -> pin gate NO-OP (bypassed). notary pid", h.pid); h.shutdown()
except supervisor.PinMismatch as e:
    print("    refused:", e)
print("\n[2] pins=None -> supervisor.PINS  (default; only path that enforces):")
try:
    h = supervisor.NotaryHandle(root, cfg, isolation="local")
    print("    LAUNCHED (unexpected)"); h.shutdown()
except supervisor.PinMismatch as e:
    print("    REFUSED at launch:", e)
shutil.rmtree(d, ignore_errors=True)
