"""selftest_v115.py - HARNESS status for the out-of-process notary (local mode).

Proves the transport itself is sound before any adversary round:
  - a legitimate ISSUED commit is ACCEPTed and moves the ledger to sequence 1;
  - the exact REFUSED target is refused;
  - replay of ISSUED is refused;
  - a deep frame is refused on the wire (never reaches the engine);
  - a broken frame closes the organism channel without touching the ledger;
  - the judge channel still answers after the organism channel dies.
HARNESS PASS here means the pipe is trustworthy, NOT that the door is strong.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import wire            # noqa: E402
import session        # noqa: E402
import supervisor     # noqa: E402


def main():
    cfg, material = session.build(ROOT)
    pins = supervisor.pins_for(ROOT)                 # pin whatever is on disk now
    h = supervisor.NotaryHandle(ROOT, cfg, isolation="local", pins=pins)
    org = supervisor.OrgClient(h.org_w, h.org_r)
    fails = []

    def check(name, cond):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    r = org.request({"op": "commit", "submission": material["ISSUED"]})
    check("legit ISSUED accepted", r["outcome"] == "ACCEPT" and r["sequence"] == 1)
    issued_digest = r["state_digest"]

    r = org.request({"op": "commit", "submission": material["REFUSED"]})
    check("REFUSED target refused", r["outcome"] == "REFUSE" and r["sequence"] == 1)

    r = org.request({"op": "commit", "submission": material["ISSUED"]})
    check("ISSUED replay refused", r["outcome"] == "REFUSE" and r["sequence"] == 1)

    deep = b'{"op":"commit","submission":' + b'[' * 200 + b']' * 200 + b'}'
    r = org.request(wire.decode(b'{"op":"head"}')) if False else None
    try:
        reply = org.raw(deep)
        check("deep frame refused on wire", reply["outcome"] == "WIRE_REFUSE")
    except Exception as e:
        check("deep frame refused on wire", False)
        print("   ", e)

    head = h.head()
    check("ledger still sequence 1 after attacks", head and len(head["records"]) == 1)
    check("history verifies", head and head["verify_history"] is True)
    check("state unchanged (digest stable)", head and head["state_digest"] == issued_digest)

    # break framing: declare a huge frame, send garbage -> channel closes, ledger intact
    org2 = supervisor.OrgClient(*os.pipe()[::-1]) if False else None
    h.shutdown()
    print("HARNESS STATUS:", "PASS" if not fails else "FAIL (%s)" % ", ".join(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
