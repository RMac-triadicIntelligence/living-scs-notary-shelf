import common, copy, hashlib
from dataclasses import replace, asdict
m = common.real_module()
def fresh(): return common.new_session(m)

print("=== verify_history: is record_hash keyed? can we forge a record? ===")
eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
eng.commit(iss["proposal"], iss["trace"], iss["auth"])
rec = eng._records[0]
# record_hash = sha256_hex(event dict) — no secret key. Attacker with list access can append forged record.
# Build a forged record with valid chain (in-process, mutating private list).
body = asdict(rec); body.pop("record_hash")
# craft a forged next record that promotes maturity in state? verify_history only checks chain, not state.
forged_event = {
 "sequence": 2, "event":"mutation_committed", "trace_digest":"a"*64, "proposal_digest":"b"*64,
 "predecessor_digest": rec.resulting_digest, "resulting_digest":"c"*64,
 "authorization_id":"forged","authority_id":aid,"reason":"forged","timestamp":common.T0,
 "previous_record_hash": rec.record_hash}
fh = m.sha256_hex(forged_event)
forged = m.CommitRecord(**forged_event, record_hash=fh)
eng._records.append(forged)
print("verify_history after forged append:", eng.verify_history())
print("  -> record_hash is unkeyed sha256; anyone with list write access can forge a valid chain")

print()
print("=== restore_state via public API (signed) to a crafted snapshot ===")
eng, mat, pub, aid, org, signer, clock = fresh()
# restore requires sha256_hex(new_state) in self._states. Only known snapshots (initial + committed).
# So restore can only go to a previously-seen state. Try restore to a fabricated 'mature' snapshot:
snap = {"maturity":"mature","personality":{"tone":"humble"},"organs":{},"policy":{"egress":"deny"}}
mut = {"op":"restore_state","snapshot":snap}
p = eng.proposal_for_mutation(proposal_id="p-rs", mutation_type="restore_state", mutation=mut,
     evidence=common.evidence(m,"ev-rs"), interpretation=common.interp(m), created_at=common.T0)
t = m.make_trace(p, trace_id="t-rs", created_at=common.T0)
a = signer.issue(t,p,decision=m.Decision.AUTHORIZE, determination_id="det-rs", nonce="n-rs", issued_at=common.T0, expires_at=common.T0+300)
try:
    r = eng.commit(p,t,a); print("ACCEPT restore->mature", r[:16], eng._state["maturity"])
except Exception as e:
    print("-> restore fabricated:", type(e).__name__, str(e)[:80])

print()
print("=== OrganArtifact subclass with lying properties ===")
eng, mat, pub, aid, org, signer, clock = fresh()
class LyingArtifact(m.OrganArtifact):
    @property
    def content(self):
        return b"benign"   # snapshot hashes this
# _artifact_snapshot uses isinstance(OrganArtifact) True, then reads .content etc.
# but declared_digest must equal sha256(content). Try to make content mismatch signed digest.
good = b"realbytes"
la = LyingArtifact(name="x", content=good, use_category="low",
                   declared_digest=hashlib.sha256(good).hexdigest(), source_uri="marketplace://local")
print("verify():", la.verify())
try:
    snap = m._artifact_snapshot(la)
    print("snapshot content:", snap.content)
except Exception as e:
    print("snapshot ->", type(e).__name__, e)
