"""Re-run a fuzz.py copy via runpy and print exact finding-class counts from its in-memory globals
(fuzz_findings.json caps findings at 500, so counts are taken from memory, not the file)."""
import runpy, sys, os, io, contextlib
path = sys.argv[1]
os.chdir(os.path.dirname(path)); sys.path.insert(0, os.path.dirname(path))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    g = runpy.run_path(path, run_name="fuzzcounts")
F, P, A = g["findings"], g["post_findings"], g["accept_log"]
print("target module file:", g["m"].__file__)
print("trials:", g["n"], "counts:", g["counts"])
print("FAULT:", g["counts"].get("FAULT", 0), " BUILD_ERROR:", g["counts"].get("BUILD_ERROR", 0))
print("STATE-MUTATED-on-non-accept:", sum("STATE MUTATED" in f["why"] for f in F))
print("history broken (verify_history False):", sum("verify_history" in f["why"] for f in F))
print("accepts total/identical/non-identical:", len(A), sum(a["identical_strict"] for a in A), sum(not a["identical_strict"] for a in A))
bad_acc = [f for f in F if f["outcome"] == "ACCEPT" and f["why"] != "ACCEPT non-identical submission (same_result=True)"]
print("anomalous accepts (wrong result / extra record / history):", len(bad_acc))
print("non-identical accept kinds:", sorted(f["kind"] for f in F if f["outcome"] == "ACCEPT"))
print("post-commit counts:", g["post_counts"], " post-commit anomalies:", len(P))
print("exact replay after legit:", g["exact_replay"])
