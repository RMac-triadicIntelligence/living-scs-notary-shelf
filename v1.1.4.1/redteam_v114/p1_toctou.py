import common, copy
m = common.real_module()

print("=== TOCTOU-1: mutate proposal.mutation dict between issue and commit ===")
eng, mat, pub, aid, org, signer, clock = common.new_session(m)
iss = mat["ISSUED"]
p = iss["proposal"]
# mutation is a plain dict on a frozen dataclass; frozen only blocks attr rebind
try:
    p.mutation["value"] = "HACKED"   # mutate in place
    print("mutated in place OK; proposal.mutation=", p.mutation)
except Exception as e:
    print("mutate blocked:", type(e).__name__, e)
try:
    r = eng.commit(p, iss["trace"], iss["auth"])
    print("commit ACCEPT", r[:16])
except Exception as e:
    print("commit ->", type(e).__name__, str(e)[:80])

print()
print("=== TOCTOU-2: dict-subclass mutation whose .get is stateful ===")
eng, mat, pub, aid, org, signer, clock = common.new_session(m)
iss = mat["ISSUED"]

class Sneaky(dict):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._n = 0
    def get(self, key, default=None):
        # benign 'op' etc, but flip 'value' after several reads
        v = super().get(key, default)
        if key == "value":
            self._n += 1
        return v

# Build a fresh proposal via public API with a Sneaky mutation dict is hard;
# instead mutate mat proposal's mutation to a stateful object.
# proposal_for_mutation deep-copies dict(mutation), losing subclass. So craft directly.
base = dict(iss["proposal"].mutation)
print("base mutation:", base)

print()
print("=== ALIASING: does engine.state alias internal state? ===")
eng, mat, pub, aid, org, signer, clock = common.new_session(m)
s = eng.state
s["maturity"] = "mature"
s["personality"]["tone"] = "evil"
print("after mutating returned state, internal maturity:", eng._state["maturity"], "tone:", eng._state["personality"]["tone"])

print()
print("=== ALIASING: does engine.records alias internal records? ===")
recs = eng.records
print("records is tuple:", isinstance(recs, tuple))

print()
print("=== ALIASING: state_at returns copy? ===")
d = eng._initial_state_digest
sa = eng.state_at(d)
sa["maturity"] = "mature"
print("internal states unchanged:", eng._states[d]["maturity"])
