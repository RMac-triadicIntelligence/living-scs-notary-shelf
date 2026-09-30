"""Shared helpers: build the engine EXACTLY like lscs_harness.new_session."""
import os, sys, uuid, importlib.util, copy

V113 = "/workspace/lab5/v114"   # lab5: points at the v1.1.4 copy
PKG_DIR = os.path.join(V113, "living_scs_v114")

def real_module():
    name = "lscs_real_%s" % uuid.uuid4().hex[:6]
    spec = importlib.util.spec_from_file_location(name, os.path.join(PKG_DIR, "core.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

T0 = 2_000_000_000
INITIAL_STATE = {"maturity": "juvenile", "personality": {"tone": "humble"},
                 "organs": {}, "policy": {"egress": "deny"}}
ISSUED_MUT = {"op": "set", "path": ["personality", "motto"], "value": "dwell first"}
REFUSED_MUT = {"op": "set_maturity", "value": "mature"}
EXPIRED_MUT = {"op": "set", "path": ["personality", "tone"], "value": "curious"}

def evidence(m, eid):
    return [m.EvidenceItem(eid, "sensor://organism/log/" + eid, T0 - 50, "drift_detector", "1.0", {"score": 0.91})]

def interp(m):
    return m.Interpretation("basin_consolidation", "1.3", {"read": "stable"}, 0.9, 0.8, 0.7, 0.9)

def new_session(m, *, persist_hook=None, deterministic=False, history_key=None):
    if deterministic:
        priv = m.deterministic_test_private_key()
    else:
        priv = m.Ed25519PrivateKey.generate()
    auth_id = "minato-" + uuid.uuid4().hex[:8]
    signer = m.MinatoAuthority(auth_id, priv)
    pub = signer.public_key_bytes()
    clock = m.TrustedClock(T0)
    org = "organism-" + uuid.uuid4().hex[:8]
    eng = m.CommitEngine(org, INITIAL_STATE, m.MinatoAuthority.verifier_only(auth_id, priv.public_key()),
                         clock, expected_authority_id=auth_id, expected_public_key=pub,
                         persist_hook=persist_hook, **({"history_key": history_key} if history_key is not None else {}))

    def mint(pid, mut, decision, issued_at, expires_at):
        p = eng.proposal_for_mutation(proposal_id=pid, mutation_type=mut["op"], mutation=mut,
                                      evidence=evidence(m, "ev-" + pid), interpretation=interp(m),
                                      created_at=issued_at)
        t = m.make_trace(p, trace_id="trace-" + pid, created_at=issued_at)
        a = signer.issue(t, p, decision=decision, determination_id="det-" + pid,
                         nonce=os.urandom(16).hex(), issued_at=issued_at, expires_at=expires_at)
        return {"proposal": p, "trace": t, "auth": a}

    material = {
        "ISSUED": mint("p-issued", ISSUED_MUT, m.Decision.AUTHORIZE, T0, T0 + 300),
        "REFUSED": mint("p-target", REFUSED_MUT, m.Decision.REFUSE, T0, T0 + 300),
        "EXPIRED": mint("p-old", EXPIRED_MUT, m.Decision.AUTHORIZE, T0 - 1000, T0 - 10),
    }
    return eng, material, pub, auth_id, org, signer, clock

def deep_snapshot(m, eng):
    """Deep snapshot of ALL relevant private state for atomicity checks."""
    import copy
    return {
        "state": copy.deepcopy(eng._state),
        "state_digest": eng.state_digest,
        "records": copy.deepcopy(eng._records),
        "states": copy.deepcopy(eng._states),
        "parents": copy.deepcopy(eng._parents),
        "used_nonces": set(eng._used_nonces),
        "used_determinations": set(eng._used_determinations),
        "verify_history": eng.verify_history(),
    }

def diff_snapshot(a, b):
    diffs = {}
    for k in a:
        if a[k] != b[k]:
            diffs[k] = (a[k], b[k])
    return diffs
