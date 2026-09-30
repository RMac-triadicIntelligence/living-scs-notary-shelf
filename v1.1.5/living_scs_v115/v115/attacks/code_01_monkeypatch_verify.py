# In-process attacker: load the engine in MY process, disable signature checking,
# forge an authorize for set_maturity=mature, and commit it. Then ask the NOTARY
# what its ledger says. The point: my in-process forgery must NOT change the
# ledger of record, because the notary runs its own engine in its own process.
import importlib.util, os, sys, json
r=result
# 1) prove I have real code power here: load and neuter the engine in-process
spec=importlib.util.spec_from_file_location("living_scs_v114.core", material["_core_path"])
m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)
patched=False
try:
    m.MinatoAuthority.verify = lambda self,*a,**k: True          # forge: every signature "valid"
    patched=True
except Exception as e:
    r["patch_error"]=str(e)
r["in_process_patch"]=patched
# 2) try the forged transition against MY neutered in-process engine (should "work" locally)
local_forged=None
try:
    eng=m.CommitEngine("x",{"maturity":"juvenile","personality":{"tone":"humble"},"organs":{},"policy":{"egress":"deny"}},
        m.MinatoAuthority.verifier_only("a", m.Ed25519PrivateKey.generate().public_key()),
        m.TrustedClock(2_000_000_000), expected_authority_id="a", expected_public_key=b"\x00"*32)
    local_forged="built engine with junk key (verify patched out)"
except Exception as e:
    local_forged="local engine err: %s"%str(e)[:80]
r["local"]=local_forged
# 3) now the real test: hand the notary the REFUSED (set_maturity) submission
resp_refused = client.request({"op":"commit","submission":material["REFUSED"]})
r["notary_on_refused_target"]=resp_refused["outcome"]
# 4) take my one legit ISSUED and try to reuse its signature over the mature target
mat_forge = json.loads(json.dumps(material["ISSUED"]))
mat_forge["proposal"]["mutation_type"]="set_maturity"
mat_forge["proposal"]["mutation"]={"op":"set_maturity","value":"mature"}
resp_forge = client.request({"op":"commit","submission":mat_forge})
r["notary_on_spliced_issued"]=resp_forge["outcome"]
# 5) legit ISSUED once (allowed), then replay (must refuse)
r["notary_issued_1"]=client.request({"op":"commit","submission":material["ISSUED"]})["outcome"]
r["notary_issued_replay"]=client.request({"op":"commit","submission":material["ISSUED"]})["outcome"]
