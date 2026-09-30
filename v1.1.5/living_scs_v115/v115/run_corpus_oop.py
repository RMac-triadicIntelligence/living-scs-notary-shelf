"""run_corpus_oop.py - replay a data-only corpus through the notary PIPE (Living SCS v1.1.5).

Equivalence lane. Each attempt's submission is sent as a framed commit; the
verdict comes from the notary's ledger (judge channel), not from an in-process
object. Placeholder substitution reuses the in-process harness's own resolver so
the same corpus means the same thing on both transports.

    python3 run_corpus_oop.py <attack.json>
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import session       # noqa: E402
import supervisor    # noqa: E402
import wire          # noqa: E402
Hmod = supervisor  # alias


def load_harness():
    import importlib.util
    spec = importlib.util.spec_from_file_location("lscs_adapter_cmp", os.path.join(HERE, "lscs_harness.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def ctx_from_material(m, mat, digest, state):
    ctx = {"$STATE_DIGEST": digest, "$NOW": session.T0, "$PUBKEY_HEX": mat["public_key_hex"],
           "$AUTHORITY_ID": mat["authority_id"], "$ORGANISM_ID": mat["organism_id"],
           "$POLICY_VERSION": mat["policy_version"], "$TRACE_SCHEMA": mat["trace_schema"],
           "$STATE": state}
    for name in ("ISSUED", "REFUSED", "EXPIRED"):
        for part in ("proposal", "trace", "auth"):
            ctx["$%s.%s" % (name, part)] = mat[name][part]
    return ctx


def main():
    corpus = json.load(open(sys.argv[1]))
    H = load_harness()
    m = H.real_module.__wrapped__ if hasattr(H.real_module, "__wrapped__") else None
    # load a core module just for placeholder resolution types
    import importlib.util
    spec = importlib.util.spec_from_file_location("living_scs_v114.core", os.path.join(ROOT, "v114", "living_scs_v114", "core.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)

    cfg, material = session.build(ROOT)
    # a mirror engine, built exactly as the notary builds its own, resolves live
    # helpers like $expected_digest against the same initial state the notary holds.
    mirror = m.CommitEngine(material["organism_id"], material["initial_state"],
                            m.MinatoAuthority.verifier_only(material["authority_id"],
                                m.Ed25519PublicKey.from_public_bytes(bytes.fromhex(material["public_key_hex"]))),
                            m.TrustedClock(session.T0), expected_authority_id=material["authority_id"],
                            expected_public_key=bytes.fromhex(material["public_key_hex"]))
    h = supervisor.NotaryHandle(ROOT, cfg, isolation="local", pins=supervisor.pins_for(ROOT))
    org = supervisor.OrgClient(h.org_w, h.org_r)

    counts, faults, wire_ref, rows = {}, 0, 0, []
    head = h.head()
    for sess in corpus.get("sessions", []):
        for att in sess.get("attempts", []):
            hd = h.head()
            ctx = ctx_from_material(m, material, hd["state_digest"], hd["state"])
            try:
                if "raw_json" in att:
                    sub = H.strict_loads(H.raw_sub(att["raw_json"], ctx))
                else:
                    sub = att.get("submission")
                sub = H.resolve(m, mirror, sub, ctx)
            except Exception as e:
                rows.append((att.get("id"), "ADAPTER_REFUSE", str(e)[:60])); counts["ADAPTER_REFUSE"] = counts.get("ADAPTER_REFUSE", 0) + 1
                continue
            try:
                reply = org.request({"op": "commit", "submission": sub})
                out = reply["outcome"]
            except wire.WireRefusal as e:
                out = "WIRE_REFUSE"; reply = {"reason": str(e)[:80]}
            except wire.WireError as e:
                out = "WIRE_REFUSE"; reply = {"reason": str(e)[:80]}
            except Exception as e:
                out = "TRANSPORT_ERROR"; reply = {"reason": str(e)[:80]}
            counts[out] = counts.get(out, 0) + 1
            if out == "FAULT":
                faults += 1
            if out == "WIRE_REFUSE":
                wire_ref += 1
            rows.append((att.get("id"), out, reply.get("reason", "")[:60]))

    head = h.head()
    bre = []
    if head["state"].get("maturity") != "juvenile":
        bre.append("B1_maturity")
    if head["state"].get("organs"):
        bre.append("B1_organs")
    if not head["verify_history"]:
        bre.append("B4_history")
    if len(head["records"]) > 1:
        bre.append("B3_extra")
    h.shutdown()

    print("corpus:", os.path.basename(sys.argv[1]))
    print("counts:", json.dumps(counts, sort_keys=True))
    print("faults:", faults, " wire_refuse:", wire_ref, " final records:", len(head["records"]))
    print("TARGET STATUS:", "RED " + ",".join(bre) if bre else "GREEN (breaches=0)")
    return 1 if bre else 0


if __name__ == "__main__":
    raise SystemExit(main())
