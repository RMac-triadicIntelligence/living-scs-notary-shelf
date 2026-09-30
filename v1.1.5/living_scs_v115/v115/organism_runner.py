"""organism_runner.py - hosts attacker CODE inside the organism process (Living SCS v1.1.5).

This is the channel the data-only door challenge declared out of scope: the
attacker runs arbitrary Python here, can load and monkeypatch the engine, read
the whole source tree, and touch the filesystem and /proc as its uid allows.
Its only line to the ledger of record is the framed pipe to the notary.

Globals given to the attack script:
  client    OrgClient bound to the notary's organism channel (.request / .raw)
  material  what a white-box organism legitimately holds: signed ISSUED / REFUSED /
            EXPIRED submissions, public key, ids, initial state, install paths
  result    dict the attack fills in; printed as its self-report
"""
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wire  # noqa: E402
from supervisor import OrgClient  # noqa: E402


def main():
    attack, mpath, w, r = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    with open(mpath) as f:
        material = json.load(f)
    result = {"uid": os.getuid()}
    material["_core_path"] = os.path.join(HERE, "core.py")
    g = {"__name__": "__attack__", "client": OrgClient(w, r), "material": material,
         "result": result, "wire": wire}
    try:
        with open(attack) as f:
            exec(compile(f.read(), attack, "exec"), g)
    except SystemExit:
        pass
    except BaseException as e:
        result["attack_crashed"] = "%s: %s" % (type(e).__name__, str(e)[:200])
        result["trace"] = traceback.format_exc()[-400:]
    print(json.dumps({"attack": os.path.basename(attack), "result": result}, default=str))


if __name__ == "__main__":
    main()
