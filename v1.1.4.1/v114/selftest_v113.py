"""Harness status for the v1.1.3 lane. Must PASS before any adversary result counts."""
import json, sys
import lscs_harness as h

EXPECTED_KILLED = {"M1", "M2", "M4"}
# Survivors, by reason (preregistered):
#   M3  replay also blocked by predecessor/fork check (guarded twice)
#   M5,M8,M9  signer / constructor seams - not reachable from a data-only channel
#   M10,M11   require Python object injection (overridden verify / __bytes__)
#   M6,M12    require a signature over a policy-violating transition; none exists
#   M7        BOM reporting, not the commit path

data = json.load(open("lscs_baseline.json"))
real = h.run_file(data, h.real_module())
mism = [(r["name"], x["id"], x["outcome"], x["expect"]) for r in real for x in r["rows"] if not x["matches_expect"]]
br = [b for r in real for b in r["breaches"]]
print("real engine: %d mismatches, %d breaches" % (len(mism), len(br)))
for m in mism: print("  MISMATCH", m)
killed = {mid for mid, _, mm in h.package_mutants() if any(r["breaches"] for r in h.run_file(data, mm))}
print("killed:", sorted(killed, key=lambda s: int(s[1:])), " expected:", sorted(EXPECTED_KILLED))
ok = not mism and not br and killed == EXPECTED_KILLED
print("HARNESS STATUS:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
