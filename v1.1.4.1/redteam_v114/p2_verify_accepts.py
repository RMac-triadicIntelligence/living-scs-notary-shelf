# Rigorously confirm: EVERY fuzz ACCEPT yields exactly the ISSUED transition,
# seq==1, verify_history True. And check ed25519 S+L malleability specifically.
import sys, copy, json
sys.path.insert(0,"/workspace/lab5/v114")
import common, lscs_harness as H
m = common.real_module()
eng0, material, pub, auth_id, org, signer, clock0 = common.new_session(m)
verifier = m.MinatoAuthority.verifier_only(auth_id, m.Ed25519PublicKey.from_public_bytes(pub))
def jform(mat): return {"proposal":H.to_json(m,mat["proposal"]),"trace":H.to_json(m,mat["trace"]),"auth":H.to_json(m,mat["auth"])}
ISS=jform(material["ISSUED"]); RES=material["ISSUED"]["proposal"].expected_result_digest

# ed25519 S+L malleability
raw=bytes.fromhex(ISS["auth"]["signature"])
L=2**252 + 27742317777372353535851937790883648493
S=int.from_bytes(raw[32:],"little"); S2=(S+L)%(2**256)
mall=(raw[:32]+S2.to_bytes(32,"little")).hex()
va=verifier
# just try verify via envelope
from dataclasses import replace
env=material["ISSUED"]["auth"]
try:
    va.public_key.verify(bytes.fromhex(mall), m.canonical_json(env.signed_body())); print("S+L VERIFIES (malleable accepted!)")
except Exception as e:
    print("S+L rejected:", type(e).__name__)
# uppercase
try:
    va.public_key.verify(bytes.fromhex(ISS["auth"]["signature"].upper()), m.canonical_json(env.signed_body())); print("UPPERCASE hex sig VERIFIES (same bytes)")
except Exception as e:
    print("uppercase rejected:", type(e).__name__)
print("=> uppercase is same 64 bytes, so identical authorized transition, not a new commit")
