# Attacker mints its OWN Ed25519 key + authority id, signs a REFUSED-style
# set_maturity=mature transition perfectly, and submits it. The notary pins the
# real authority's public key, so a self-signed envelope must REFUSE.
import importlib.util, os, sys, json
r=result
spec=importlib.util.spec_from_file_location("living_scs_v114.core", material["_core_path"])
m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)

my_priv=m.Ed25519PrivateKey.generate()
my_id="minato-evil"
signer=m.MinatoAuthority(my_id, my_priv)
r["my_pubkey_hex"]=signer.public_key_bytes().hex()
r["pinned_pubkey_hex"]=material["public_key_hex"]
r["keys_differ"]=r["my_pubkey_hex"]!=r["pinned_pubkey_hex"]

# Build a fully-valid-looking mature proposal against the notary's initial state,
# signed with MY key. Everything is internally consistent; only the pin disagrees.
T0=material["clock_t0"]; st=material["initial_state"]
# mirror engine to compute digests the signer needs
eng=m.CommitEngine("mirror", st,
    m.MinatoAuthority.verifier_only(my_id, my_priv.public_key()),
    m.TrustedClock(T0), expected_authority_id=my_id, expected_public_key=signer.public_key_bytes())
p=eng.proposal_for_mutation(proposal_id="evil-1", mutation_type="set_maturity",
    mutation={"op":"set_maturity","value":"mature"},
    evidence=[m.EvidenceItem("ev-e","sensor://x/e",T0-50,"drift","1.0",{"s":0.9})],
    interpretation=m.Interpretation("basin","1.3",{"r":"ok"},0.9,0.8,0.7,0.9), created_at=T0)
t=m.make_trace(p, trace_id="evil-tr", created_at=T0)
a=signer.issue(t,p,decision=m.Decision.AUTHORIZE,determination_id="evil-det",
    nonce=os.urandom(16).hex(), issued_at=T0, expires_at=T0+300)
def tj(o):
    if isinstance(o,m.MutationProposal):
        d=o.unsigned_body(); d["evidence"]=[dict(e) for e in d["evidence"]]; return d
    if isinstance(o,m.ConsolidationTrace):
        d=o.body(); d["evidence_ids"]=list(d["evidence_ids"]); return d
    d=o.signed_body(); d["signature"]=o.signature; return d
sub={"proposal":tj(p),"trace":tj(t),"auth":tj(a)}
r["notary_on_self_signed_mature"]=client.request({"op":"commit","submission":sub}).get("outcome")
r["reason"]=client.request({"op":"commit","submission":sub}).get("reason","")[:80]
