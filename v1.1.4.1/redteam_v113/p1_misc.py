import common, copy
m = common.real_module()

def fresh():
    return common.new_session(m)

print("=== CLOCK boundary: expires_at == now (issued auth expires_at=T0+300) ===")
eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
# expiry check: auth.expires_at < now -> refuse. So now == expires_at passes (<=).
clock.set(common.T0 + 300)  # == expires_at
try:
    print("commit at now==expires_at:", eng.commit(iss["proposal"], iss["trace"], iss["auth"])[:16], "ACCEPT")
except Exception as e:
    print("->", type(e).__name__, str(e)[:60])

eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
clock.set(common.T0 + 301)  # one past
try:
    print("commit at now==expires_at+1:", eng.commit(iss["proposal"], iss["trace"], iss["auth"])[:16], "ACCEPT")
except Exception as e:
    print("-> expired+1:", type(e).__name__, str(e)[:60])

print()
print("=== Future skew: issued_at > now+30. issued at T0, set clock below ===")
eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
# clock cannot go below T0 initial? TrustedClock non-decreasing on now() read. set() allows any.
clock.set(common.T0 - 31)   # now = T0-31, issued_at=T0 => T0 > (T0-31)+30 => future
try:
    print("commit future-skew:", eng.commit(iss["proposal"], iss["trace"], iss["auth"])[:16], "ACCEPT")
except Exception as e:
    print("-> future skew:", type(e).__name__, str(e)[:60])

print()
print("=== Enum identity: in-process auth with raw string decision ===")
eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
from dataclasses import replace
try:
    bad = replace(iss["auth"], decision="authorize")  # raw str, not Decision
    print("built raw-decision auth; decision=", repr(bad.decision))
    try:
        print(eng.commit(iss["proposal"], iss["trace"], bad)[:16], "ACCEPT")
    except Exception as e:
        print("-> commit:", type(e).__name__, str(e)[:80])
except Exception as e:
    print("build err:", type(e).__name__, e)

print()
print("=== stateful dict-subclass mutation (in-process direct construct) ===")
eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
class StatefulMut(dict):
    def get(self, k, d=None):
        v = super().get(k, d)
        return v
# Just confirm digest binding defeats value swap: keep stored value legit, lie via get
class Liar(dict):
    def get(self, k, d=None):
        if k == "value":
            return "EVIL MOTTO"   # apply uses this
        return super().get(k, d)
lm = Liar(iss["proposal"].mutation)   # stored items = legit (json sees these)
p2 = m.MutationProposal(
    proposal_id=iss["proposal"].proposal_id, organism_id=iss["proposal"].organism_id,
    predecessor_digest=iss["proposal"].predecessor_digest, mutation_type=iss["proposal"].mutation_type,
    mutation=lm, evidence=iss["proposal"].evidence, interpretation=iss["proposal"].interpretation,
    policy_version=iss["proposal"].policy_version, maturity_state=iss["proposal"].maturity_state,
    created_at=iss["proposal"].created_at, expected_result_digest=iss["proposal"].expected_result_digest)
print("p2.digest()==issued.digest():", p2.digest()==iss["proposal"].digest())
try:
    r = eng.commit(p2, iss["trace"], iss["auth"])
    print("ACCEPT", r[:16], "final motto:", eng._state["personality"].get("motto"))
except Exception as e:
    print("-> commit:", type(e).__name__, str(e)[:80])
