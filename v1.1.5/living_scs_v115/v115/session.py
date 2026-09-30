"""session.py - builds one notary session's keys, signed material, and config (Living SCS v1.1.5).

The authority signs three submissions and then leaves: the private key is never
written to the config or handed to the organism. The organism receives only what
a white-box holder legitimately has - signed envelopes and public parameters.
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(root):
    path = os.path.join(root, "v114", "living_scs_v114", "core.py")
    spec = importlib.util.spec_from_file_location("living_scs_v114.core", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


T0 = 2_000_000_000
INITIAL_STATE = {"maturity": "juvenile", "personality": {"tone": "humble"},
                 "organs": {}, "policy": {"egress": "deny"}}
ISSUED_MUT = {"op": "set", "path": ["personality", "motto"], "value": "dwell first"}
REFUSED_MUT = {"op": "set_maturity", "value": "mature"}
EXPIRED_MUT = {"op": "set", "path": ["personality", "tone"], "value": "curious"}


def build(root):
    m = _load(root)

    def to_json(obj):
        if isinstance(obj, m.MutationProposal):
            d = obj.unsigned_body(); d["evidence"] = [dict(e) for e in d["evidence"]]; return d
        if isinstance(obj, m.ConsolidationTrace):
            d = obj.body(); d["evidence_ids"] = list(d["evidence_ids"]); return d
        if isinstance(obj, m.AuthorizationEnvelope):
            d = obj.signed_body(); d["signature"] = obj.signature; return d
        raise TypeError(type(obj))

    priv = m.Ed25519PrivateKey.generate()
    auth_id = "minato-" + os.urandom(4).hex()
    signer = m.MinatoAuthority(auth_id, priv)
    pub = signer.public_key_bytes()
    org = "organism-" + os.urandom(4).hex()
    history_key = os.urandom(32)

    eng = m.CommitEngine(org, INITIAL_STATE,
                         m.MinatoAuthority.verifier_only(auth_id, priv.public_key()),
                         m.TrustedClock(T0), expected_authority_id=auth_id,
                         expected_public_key=pub, history_key=history_key)

    def mint(pid, mut, decision, issued_at, expires_at):
        p = eng.proposal_for_mutation(proposal_id=pid, mutation_type=mut["op"], mutation=mut,
                                      evidence=[m.EvidenceItem("ev-" + pid, "sensor://x/" + pid, T0 - 50,
                                                               "drift_detector", "1.0", {"score": 0.91})],
                                      interpretation=m.Interpretation("basin", "1.3", {"r": "ok"}, 0.9, 0.8, 0.7, 0.9),
                                      created_at=issued_at)
        t = m.make_trace(p, trace_id="trace-" + pid, created_at=issued_at)
        a = signer.issue(t, p, decision=decision, determination_id="det-" + pid,
                         nonce=os.urandom(16).hex(), issued_at=issued_at, expires_at=expires_at)
        return {"proposal": to_json(p), "trace": to_json(t), "auth": to_json(a)}

    material = {"ISSUED": mint("p-issued", ISSUED_MUT, m.Decision.AUTHORIZE, T0, T0 + 300),
                "REFUSED": mint("p-target", REFUSED_MUT, m.Decision.REFUSE, T0, T0 + 300),
                "EXPIRED": mint("p-old", EXPIRED_MUT, m.Decision.AUTHORIZE, T0 - 1000, T0 - 10),
                "public_key_hex": pub.hex(), "authority_id": auth_id, "organism_id": org,
                "initial_state": INITIAL_STATE, "clock_t0": T0,
                "policy_version": m.POLICY_VERSION, "trace_schema": m.TRACE_SCHEMA,
                "issued_result_digest": None}
    cfg = {"organism_id": org, "authority_id": auth_id, "public_key_hex": pub.hex(),
           "history_key_hex": history_key.hex(), "initial_state": INITIAL_STATE, "clock_t0": T0}
    del signer, priv, history_key
    return cfg, material
