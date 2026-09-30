"""Genuinely signed proposal with {"op":"set","path":5}: every gate passes, apply_mutation raises TypeError."""
import sys, importlib.util
for label, path in (("v113", "/workspace/lab5/v113_ref/living_scs_v113/core.py"), ("v114", "/workspace/lab5/v114/living_scs_v114/core.py")):
    spec = importlib.util.spec_from_file_location("m_" + label, path); m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m; spec.loader.exec_module(m)
    NOW = 1_800_000_000
    signer = m.MinatoAuthority("root", m.deterministic_test_private_key())
    eng = m.CommitEngine("org", {"maturity": "juvenile", "personality": {}, "organs": {}, "policy": "p"},
                         m.MinatoAuthority.verifier_only("root", signer.public_key), m.TrustedClock(NOW),
                         expected_authority_id="root", expected_public_key=signer.public_key_bytes())
    ev = (m.EvidenceItem("e", "memory://x/0", NOW, "rule_counter", "1", {}),)
    it = m.Interpretation("m", "1", {"o": 1}, 0.9, 0.9, 0.5, 0.5)
    p = m.MutationProposal("p", "org", eng.state_digest, "drift", {"op": "set", "path": 5, "value": 1}, ev, it,
                           m.POLICY_VERSION, "juvenile", NOW, "e" * 64)
    t = m.make_trace(p, trace_id="t", created_at=NOW)
    a = signer.issue(t, p, decision=m.Decision.AUTHORIZE, determination_id="d", nonce="n", issued_at=NOW, expires_at=NOW + 60)
    try:
        eng.commit(p, t, a); print(label, "ACCEPT")
    except m.Refusal as e:
        print(label, "Refusal:", e, "| cause:", type(e.__cause__).__name__, "| records:", len(eng.records))
    except Exception as e:
        print(label, "RAW", type(e).__name__, e, "| records:", len(eng.records))
