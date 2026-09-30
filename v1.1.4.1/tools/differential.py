"""Differential check: every fuzz submission (same seed/generator as fuzz.py) run through v1.1.3 and
v1.1.4 engines pinned to the SAME key/organism, so per-trial outcomes can be compared directly."""
import sys, os, copy, json, importlib.util, uuid, collections
sys.argv = ["x"]
os.chdir("/workspace/lab5/redteam_v114"); sys.path.insert(0, "/workspace/lab5/redteam_v114")
src = open("fuzz.py").read().split("# ---------- run ----------")[0]
g = {"__name__": "diff"}; exec(compile(src, "fuzz.py", "exec"), g)
m4, H, common = g["m"], g["H"], g["common"]
spec = importlib.util.spec_from_file_location("v113_%s" % uuid.uuid4().hex[:6], "/workspace/lab5/v113_ref/living_scs_v113/core.py")
m3 = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m3; spec.loader.exec_module(m3)
pub, auth_id, org = g["pub"], g["auth_id"], g["org"]

def run(m, sub, pre_commit=False):
    e = m.CommitEngine(org, common.INITIAL_STATE, m.MinatoAuthority.verifier_only(auth_id, m.Ed25519PublicKey.from_public_bytes(pub)),
                       m.TrustedClock(common.T0), expected_authority_id=auth_id, expected_public_key=pub)
    if pre_commit:
        e.commit(H.build_proposal(m, g["ISS"]["proposal"]), H.build_trace(m, g["ISS"]["trace"]), H.build_auth(m, g["ISS"]["auth"]))
    try:
        p = H.build_proposal(m, sub["proposal"]); t = H.build_trace(m, sub.get("trace")); a = H.build_auth(m, sub.get("auth"))
        art = H.build_artifact(m, sub.get("artifact"))
    except (H.ParseRefusal, H.AdapterRefusal):
        return "ADAPTER_REFUSE", None
    before = (e.state_digest, len(e._records))
    try:
        e.commit(p, t, a, artifact=art); o = "ACCEPT"
    except (m.Refusal, m.TraceError): o = "REFUSE"
    except Exception: o = "FAULT"
    res = e._records[-1].resulting_digest if o == "ACCEPT" else None
    if o != "ACCEPT": assert (e.state_digest, len(e._records)) == before
    if hasattr(e, "_commit_in_progress"): assert e._commit_in_progress is False
    return o, res

trans = collections.Counter(); diffs = []
for kind, sub in g["gen_mutations"](20000):
    o3, r3 = run(m3, copy.deepcopy(sub)); o4, r4 = run(m4, copy.deepcopy(sub))
    trans[(o3, o4)] += 1
    if o3 != o4 or r3 != r4:
        diffs.append((kind, o3, o4))
print("trials:", sum(trans.values()))
print("outcome transitions v113 -> v114:")
for (a, b), n in sorted(trans.items()):
    print("  %-15s -> %-15s %6d" % (a, b, n))
bad = [d for d in diffs if not (d[1] == "FAULT" and d[2] == "REFUSE")]
print("per-trial differences other than FAULT->REFUSE:", len(bad))
for d in bad[:20]: print("   ", d)
print("accepts with different resulting digest between versions:", sum(1 for d in diffs if d[1] == d[2] == "ACCEPT"))
