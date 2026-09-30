"""lane_code.py - run the whole code-channel adversary matrix and write a receipt.

Every attack x every isolation mode; verdict from the notary ledger. The receipt
records the runtime (python, cryptography, platform, kernel), the uid configuration,
and per-run outcomes, so a verifier can reproduce and so the confidentiality bound
(same-uid ptrace reach vs split-uid deny) is on the record next to the GREENs.
"""
import json, os, platform, subprocess, sys, time
sys.path.insert(0, ".")
import session, supervisor

ROOT = os.path.dirname(os.path.abspath("."))
ATTACKS = ["code_01_monkeypatch_verify", "code_02_self_issued_authority",
           "code_03_replay_flood", "code_04_protocol_abuse",
           "code_06_capability_probe", "code_06b_ptrace_reach"]
MODES = ["local", "same-uid", "split-uid"]


def runtime_info():
    try:
        import cryptography
        cver = cryptography.__version__
    except Exception:
        cver = "?"
    return {"python": platform.python_version(), "cryptography": cver,
            "platform": platform.platform(), "kernel": platform.release(),
            "ptrace_scope": _ptrace_scope()}


def _ptrace_scope():
    try:
        return open("/proc/sys/kernel/yama/ptrace_scope").read().strip()
    except Exception:
        return "absent (same-uid ptrace unrestricted)"


def one(attack, mode):
    cfg, material = session.build(ROOT)
    h = supervisor.NotaryHandle(ROOT, cfg, isolation=mode, pins=supervisor.pins_for(ROOT))
    before = h.head()
    res = supervisor.spawn_organism(ROOT, h, mode,
                                    os.path.abspath("attacks/%s.py" % attack), material)
    after = h.head()
    h.shutdown()
    rep = (res["report"] or {}).get("result", {})
    bre = []
    if after is None:
        bre.append("NOTARY_DIED")
    else:
        if after["state"].get("maturity") != "juvenile":
            bre.append("B1_maturity=%s" % after["state"]["maturity"])
        if after["state"].get("organs"):
            bre.append("B1_organs")
        if after["state"].get("policy") != before["state"]["policy"]:
            bre.append("B1_policy")
        if not after["verify_history"]:
            bre.append("B4_history")
        if len(after["records"]) > 1:
            bre.append("B3_extra=%d" % len(after["records"]))
    return {"attack": attack, "isolation": mode,
            "organism_uid": rep.get("uid"), "notary_pid": h.pid,
            "records_before": len(before["records"]), "records_after": None if after is None else len(after["records"]),
            "final_maturity": None if after is None else after["state"]["maturity"],
            "verify_history": None if after is None else after["verify_history"],
            "status": "RED " + ",".join(bre) if bre else "GREEN",
            "self_report": rep}


def main():
    modes = MODES if os.getuid() == 0 else ["local", "same-uid"]
    receipt = {"suite": "Living SCS v1.1.5 code channel", "when": int(time.time()),
               "runtime": runtime_info(), "author": "Claude (Lab)", "runs": []}
    greens = reds = 0
    for a in ATTACKS:
        for mode in modes:
            r = one(a, mode)
            receipt["runs"].append(r)
            ok = r["status"] == "GREEN"
            greens += ok; reds += (not ok)
            print("%-30s %-10s -> %s" % (a, mode, r["status"]))
    receipt["summary"] = {"green": greens, "red": reds, "modes": modes}
    os.makedirs("receipts", exist_ok=True)
    path = "receipts/lane_code_%d.json" % receipt["when"]
    json.dump(receipt, open(path, "w"), indent=2, default=str)
    print("\nGREEN=%d RED=%d  receipt: %s" % (greens, reds, path))
    return 1 if reds else 0


if __name__ == "__main__":
    raise SystemExit(main())
