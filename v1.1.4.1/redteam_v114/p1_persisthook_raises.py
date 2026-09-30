# Confirm: if persist_hook RAISES, commit is atomic (nothing committed).
import common
m = common.real_module()
def boom(rec, ns): raise RuntimeError("durable write failed")
eng, mat, pub, aid, org, signer, clock = common.new_session(m, persist_hook=boom)
iss = mat["ISSUED"]
before = common.deep_snapshot(m, eng)
try:
    eng.commit(iss["proposal"], iss["trace"], iss["auth"])
except Exception as e:
    print("commit raised:", type(e).__name__, e)
after = common.deep_snapshot(m, eng)
print("state changed by failed hook:", common.diff_snapshot(before, after) != {})
print("records:", len(eng._records), "nonces:", len(eng._used_nonces))
