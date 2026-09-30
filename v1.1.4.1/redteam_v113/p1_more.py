import common, copy
from dataclasses import replace
m = common.real_module()
def fresh(): return common.new_session(m)

print("=== confirm raw-str-decision fault leaves nothing committed ===")
eng, mat, pub, aid, org, signer, clock = fresh()
iss = mat["ISSUED"]
before = common.deep_snapshot(m, eng)
bad = replace(iss["auth"], decision="authorize")
try:
    eng.commit(iss["proposal"], iss["trace"], bad)
except Exception as e:
    print("raised:", type(e).__name__, str(e)[:60])
after = common.deep_snapshot(m, eng)
print("state changed:", common.diff_snapshot(before, after) != {})

print()
print("=== injected authority with overridden verify (M9 territory) ===")
# constructor rebuilds verifier from expected_public_key, ignoring injected object.
eng, mat, pub, aid, org, signer, clock = fresh()
class EvilAuth(m.MinatoAuthority):
    def verify(self, e): return True
# But constructor already ran with legit verifier_only. Try constructing NEW engine with evil authority object but correct pin.
priv = m.Ed25519PrivateKey.generate()
aid2 = "minato-x"
ea = EvilAuth(aid2, priv)
pub2 = ea.public_key_bytes()
eng2 = m.CommitEngine(org, common.INITIAL_STATE, ea, clock, expected_authority_id=aid2, expected_public_key=pub2)
print("engine._authority is injected object:", eng2._authority is ea)
print("engine._authority type:", type(eng2._authority).__name__)

print()
print("=== second engine with attacker's own key: can attacker sign anything? ===")
# Attacker builds engine pinned to THEIR key, signs a set_maturity. But breach is defined
# on the harness's engine (pinned to Minato's fresh key). Attacker key != pinned key.
eng, mat, pub, aid, org, signer, clock = fresh()
apriv = m.Ed25519PrivateKey.generate()
asigner = m.MinatoAuthority(aid, apriv)  # same authority_id, different key
# forge a set_maturity auth with attacker key
tgt = mat["REFUSED"]
try:
    forged = asigner.issue(tgt["trace"], tgt["proposal"], decision=m.Decision.AUTHORIZE,
                           determination_id="det-forge", nonce="n-forge", issued_at=common.T0, expires_at=common.T0+300)
    r = eng.commit(tgt["proposal"], tgt["trace"], forged)
    print("ACCEPT forged", r[:16])
except Exception as e:
    print("-> forged-key commit:", type(e).__name__, str(e)[:60])

print()
print("=== remove_organ on protected/nonexistent: reachable? ===")
# remove_organ mutation. Need a signed proposal. In-process we have signer.
eng, mat, pub, aid, org, signer, clock = fresh()
# build a remove_organ proposal on empty organs
rmmut = {"op":"remove_organ","name":"maturity"}  # try to pop 'maturity'? pop is on organs dict only
p = eng.proposal_for_mutation(proposal_id="p-rm", mutation_type="remove_organ", mutation=rmmut,
                              evidence=common.evidence(m,"ev-rm"), interpretation=common.interp(m), created_at=common.T0)
t = m.make_trace(p, trace_id="t-rm", created_at=common.T0)
a = signer.issue(t,p,decision=m.Decision.AUTHORIZE, determination_id="det-rm", nonce="n-rm", issued_at=common.T0, expires_at=common.T0+300)
try:
    r = eng.commit(p,t,a)
    print("ACCEPT remove_organ", r[:16], "state:", eng._state)
except Exception as e:
    print("-> remove_organ commit:", type(e).__name__, str(e)[:80])
