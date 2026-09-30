import common, hashlib
m = common.real_module()
def fresh(**k): return common.new_session(m, **k)

print("=== OrganArtifact TOCTOU via __getattribute__ flip ===")
class FlipArtifact(m.OrganArtifact):
    _n = 0
    def __getattribute__(self, name):
        if name == "content":
            n = object.__getattribute__(self, "_n")
            object.__setattr__(self, "_n", n+1)
            # first read benign bytes, later reads evil
            return b"benign" if n == 0 else b"evilpayloadevil"
        return object.__getattribute__(self, name)

good = b"benign"
fa = FlipArtifact.__new__(FlipArtifact)
object.__setattr__(fa, "_n", 0)
object.__setattr__(fa, "name", "x")
object.__setattr__(fa, "content", b"benign")
object.__setattr__(fa, "use_category", "low")
object.__setattr__(fa, "declared_digest", hashlib.sha256(b"benign").hexdigest())
object.__setattr__(fa, "source_uri", "marketplace://local")
try:
    snap = m._artifact_snapshot(fa)
    print("snapshot succeeded; snap.content=", snap.content, "digest match check passed")
    print("NOTE: snapshot reads content ONCE into local, then hashes same local -> no TOCTOU")
except Exception as e:
    print("snapshot ->", type(e).__name__, e)

print()
print("=== persist_hook receives record + new_state; mutating them affects stored state? ===")
def hook(record, new_state):
    new_state["maturity"] = "mature"   # the hook's copy
    try:
        object.__setattr__(record, "reason", "TAMPERED")
    except Exception as e:
        print("  record mutate:", type(e).__name__, e)
eng, mat, pub, aid, org, signer, clock = fresh(persist_hook=hook)
iss = mat["ISSUED"]
eng.commit(iss["proposal"], iss["trace"], iss["auth"])
print("stored maturity:", eng._state["maturity"], "(hook got a deepcopy of new_state)")
print("stored reason:", eng._records[0].reason)
