import common, copy, traceback
m = common.real_module()

# persist_hook is a constructor-supplied callback (in-process only). RLock is reentrant.
# At the moment persist_hook runs, state/records/nonces are NOT yet updated.
calls = {"n": 0}
captured = {}

def hook(record, new_state):
    calls["n"] += 1
    if calls["n"] == 1:
        # re-enter commit with the SAME issued material during the hook
        try:
            r2 = captured["eng"].commit(captured["p"], captured["t"], captured["a"], reason="reentrant")
            captured["reentrant_result"] = r2
        except Exception as e:
            captured["reentrant_exc"] = "%s: %s" % (type(e).__name__, e)

eng, mat, pub, aid, org, signer, clock = common.new_session(m, persist_hook=hook)
iss = mat["ISSUED"]
captured.update(eng=eng, p=iss["proposal"], t=iss["trace"], a=iss["auth"])
before = common.deep_snapshot(m, eng)
try:
    r = eng.commit(iss["proposal"], iss["trace"], iss["auth"], reason="outer")
    print("outer commit result:", r[:16])
except Exception as e:
    print("outer raised:", type(e).__name__, e)
print("hook calls:", calls["n"])
print("reentrant_result:", captured.get("reentrant_result", None) and captured["reentrant_result"][:16])
print("reentrant_exc:", captured.get("reentrant_exc"))
print("num records:", len(eng._records))
print("record sequences:", [r.sequence for r in eng._records])
print("prev hashes distinct:", [r.previous_record_hash[:8] for r in eng._records])
print("verify_history:", eng.verify_history())
print("used_nonces:", len(eng._used_nonces), "used_dets:", len(eng._used_determinations))
