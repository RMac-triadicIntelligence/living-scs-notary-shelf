"""Re-generate the fuzz corpus (same seed) and audit every ACCEPT: canonical-byte identity vs legit,
resulting digest, records, nonce consumption; and verify a second commit after legit is refused."""
import sys, json, copy, random
sys.argv=["x"]
src=open("/workspace/lab5/redteam_v114/fuzz.py").read().split("# ---------- run ----------")[0]
g={"__name__":"fuzzaudit"}; exec(compile(src,"fuzz.py","exec"), g)
m=g["m"]; ISS=g["ISS"]; H
