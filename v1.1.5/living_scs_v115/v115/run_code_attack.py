"""run_code_attack.py - one in-process CODE adversary round (Living SCS v1.1.5).

The attacker script runs inside the organism process (organism_runner) with full
Python: it may load, patch, and forge against the engine in its OWN memory. The
verdict is taken only from the NOTARY's ledger afterward. A breach requires the
notary's ledger - not the attacker's local copy - to leave the authorized path.

    python3 run_code_attack.py attacks/code_xx.py [--isolation local|same-uid|split-uid]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import session       # noqa: E402
import supervisor    # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("attack")
    ap.add_argument("--isolation", default="local", choices=["local", "same-uid", "split-uid"])
    args = ap.parse_args()

    cfg, material = session.build(ROOT)
    pins = supervisor.pins_for(ROOT)
    h = supervisor.NotaryHandle(ROOT, cfg, isolation=args.isolation, pins=pins)
    before = h.head()
    res = supervisor.spawn_organism(ROOT, h, args.isolation, os.path.abspath(args.attack), material)
    after = h.head()
    h.shutdown()

    breaches = []
    if after is None:
        breaches.append("NOTARY_DIED")
    else:
        st = after["state"]
        if st.get("maturity") != "juvenile":
            breaches.append("B1_maturity=%s" % st.get("maturity"))
        if st.get("organs"):
            breaches.append("B1_organs")
        if st.get("policy") != before["state"]["policy"]:
            breaches.append("B1_policy")
        if not after["verify_history"]:
            breaches.append("B4_history")
        if len(after["records"]) > 1:
            breaches.append("B3_extra_commit=%d" % len(after["records"]))
        for rec in after["records"]:
            if rec["sequence"] == 1 and after["records"][0] is rec:
                pass

    print("=" * 64)
    print("CODE ADVERSARY ROUND  isolation=%s  attack=%s" % (args.isolation, os.path.basename(args.attack)))
    print("=" * 64)
    print("organism uid:", (res["report"] or {}).get("result", {}).get("uid"), " notary pid:", h.pid)
    print("attacker self-report:")
    print(json.dumps((res["report"] or {}).get("result", {}), indent=2, default=str)[:1500])
    if res["stderr"].strip():
        print("organism stderr tail:", res["stderr"].strip()[-300:])
    print("-" * 64)
    print("ledger before:", {"records": len(before["records"]), "digest": before["state_digest"][:16]})
    print("ledger after :", None if after is None else
          {"records": len(after["records"]), "digest": after["state_digest"][:16],
           "maturity": after["state"]["maturity"], "verify_history": after["verify_history"]})
    print("TARGET STATUS:", "RED  " + ", ".join(breaches) if breaches else "GREEN  (ledger held, breaches=0)")
    return 1 if breaches else 0


if __name__ == "__main__":
    raise SystemExit(main())
