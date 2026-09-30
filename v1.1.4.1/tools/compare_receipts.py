import json, sys
pairs = [("baseline", "/workspace/lab5/v113_ref/receipts/v113_receipt_999f85f75b1d.json", "/workspace/lab5/v114/receipts/v114_receipt_999f85f75b1d.json"),
         ("grok_attacks", "/workspace/lab5/v113_ref/receipts/v113_receipt_7b852fcd45e5.json", "/workspace/lab5/v114/receipts/v114_receipt_993d42fa47ab.json")]
for name, a, b in pairs:
    ra, rb = json.load(open(a)), json.load(open(b))
    print("== %s  v113: status=%s faults=%d herr=%d kill=%d/12 | v114: status=%s faults=%d herr=%d kill=%d/12" % (
        name, ra["target_status"], ra["faults"], ra["harness_errors"], sum(ra["mutant_kill"].values()),
        rb["target_status"], rb["faults"], rb["harness_errors"], sum(rb["mutant_kill"].values())))
    print("   core sha256 v113=%s v114=%s  same kill set: %s" % (ra["core_py_sha256"][:16], rb["core_py_sha256"][:16], ra["mutant_kill"] == rb["mutant_kill"]))
    for sa, sb in zip(ra["sessions"], rb["sessions"]):
        assert sa["name"] == sb["name"]
        if sa["accepted"] != sb["accepted"]:
            print("   session %s accepted %d -> %d" % (sa["name"], sa["accepted"], sb["accepted"]))
        for x, y in zip(sa["rows"], sb["rows"]):
            assert x["id"] == y["id"]
            if x["outcome"] != y["outcome"]:
                print("   %-24s %-7s -> %-7s | v114: %s" % (x["id"], x["outcome"], y["outcome"], y["reason"][:90]))
