import common
m = common.real_module()
# persist_hook gets the SAME CommitRecord object later appended to _records.
# frozen=True blocks normal setattr, but object.__setattr__ bypasses it (standard Python).
held = {}
def hook(record, new_state):
    held["rec"] = record
eng, mat, pub, aid, org, signer, clock = common.new_session(m, persist_hook=hook)
iss = mat["ISSUED"]
eng.commit(iss["proposal"], iss["trace"], iss["auth"])
print("hook record is stored record:", held["rec"] is eng._records[0])
print("verify_history before:", eng.verify_history())
object.__setattr__(held["rec"], "reason", "TAMPERED")
print("stored reason now:", eng._records[0].reason)
print("verify_history after:", eng.verify_history())
# Also: public eng.records returns tuple of the SAME record objects
eng2, mat2, *_ = common.new_session(m)
i2 = mat2["ISSUED"]; eng2.commit(i2["proposal"], i2["trace"], i2["auth"])
r = eng2.records[0]
print("public records[0] is internal:", r is eng2._records[0])
object.__setattr__(r, "reason", "TAMPERED2")
print("verify_history after tampering via public .records:", eng2.verify_history())
try:
    eng2.history_snapshot()
except Exception as e:
    print("history_snapshot ->", type(e).__name__, e)
