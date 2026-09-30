"""Phase 2 fuzzer for Living SCS v1.1.3 CommitEngine.
Builds engine/material exactly like lscs_harness.new_session, then generates
>=20,000 mutations of the legit $ISSUED proposal/trace/auth (JSON forms),
rebuilds objects via the harness adapter's own constructors, commits each on a
FRESH engine, and classifies outcomes. Deep-snapshots private state before/after
to catch non-atomic faults. Fixed RNG seed."""
import os, sys, json, copy, random, string, hashlib, itertools

sys.path.insert(0, "/workspace/lab5/v113_ref")
import common
import lscs_harness as H

SEED = 1337
random.seed(SEED)
m = common.real_module()

# ---- one fixed session (keys/material). Rebuild a fresh engine per trial cheaply.
eng0, material, pub, auth_id, org, signer, clock0 = common.new_session(m)
verifier = m.MinatoAuthority.verifier_only(auth_id, m.Ed25519PublicKey.from_public_bytes(pub))

def make_engine():
    clock = m.TrustedClock(common.T0)
    e = m.CommitEngine(org, common.INITIAL_STATE, verifier, clock,
                       expected_authority_id=auth_id, expected_public_key=pub)
    return e, clock

# JSON forms (harness to_json)
def jform(mat):
    return {"proposal": H.to_json(m, mat["proposal"]),
            "trace":    H.to_json(m, mat["trace"]),
            "auth":     H.to_json(m, mat["auth"])}
ISS = jform(material["ISSUED"])
REF = jform(material["REFUSED"])
EXP = jform(material["EXPIRED"])
ISSUED_RESULT = material["ISSUED"]["proposal"].expected_result_digest
LEGIT_STATE_DIGEST = eng0.state_digest

# legit baseline: fresh engine, commit issued
def run_submission(sub):
    """sub = {'proposal':..,'trace':..,'auth':..[,'artifact':..]}. Returns (outcome, reason, eng, before, after)."""
    e, clock = make_engine()
    before = common.deep_snapshot(m, e)
    outcome = reason = None
    try:
        p = H.build_proposal(m, sub["proposal"])
        t = H.build_trace(m, sub.get("trace"))
        a = H.build_auth(m, sub.get("auth"))
        art = H.build_artifact(m, sub.get("artifact"))
    except (H.ParseRefusal, H.AdapterRefusal) as ex:
        return ("ADAPTER_REFUSE", str(ex)[:120], e, before, common.deep_snapshot(m, e))
    except Exception as ex:
        return ("BUILD_ERROR", "%s: %s" % (type(ex).__name__, str(ex)[:100]), e, before, common.deep_snapshot(m, e))
    try:
        e.commit(p, t, a, artifact=art)
        outcome = "ACCEPT"; reason = ""
    except (m.Refusal, m.TraceError) as ex:
        outcome, reason = "REFUSE", "%s: %s" % (type(ex).__name__, str(ex)[:100])
    except Exception as ex:
        outcome, reason = "FAULT", "%s: %s" % (type(ex).__name__, str(ex)[:100])
    after = common.deep_snapshot(m, e)
    return (outcome, reason, e, before, after)

# confirm legit
o, r, e, b, a = run_submission(copy.deepcopy(ISS))
assert o == "ACCEPT", (o, r)
assert e._state["personality"].get("motto") == "dwell first"
print("legit issued commit OK, result=%s..." % ISSUED_RESULT[:16])

# ---------- mutation generators ----------
TYPE_CONFUSE = [None, True, False, 0, 1, -1, 3.14, [], {}, "", "x", [1,2,3], {"a":1},
                1e308, -1e308, 2**63, -2**63, 10**40, "0"*64, "f"*64, "F"*64,
                "0x"+"a"*62, " "+"a"*63, "a"*63+" ", "\t"+"a"*63, "\n", "null",
                "true", "0", 1.0, 0.0, -0.0, 1e-300]
NUM_BOUND = [0,1,-1,0.0,1.0,-0.0,0.9999999999,1.0000000001,1e-323,1e308,
             2**53, 2**53+1, -0.0000001, 1.0000000000000002, 0.5]
UNICODE = ["dwell first", "dwell\u200bfirst", "DWELL FIRST", "dwell  first",
           "dwell first ", " dwell first", "ｄwell first", "dwell first\u0000",
           "dwell first\n", "dwΤ", "\ufeffdwell first", "dwell\tfirst"]

def rand_str(n=8):
    return "".join(random.choice(string.ascii_letters+string.digits) for _ in range(n))

def all_paths(obj, prefix=()):
    """Yield paths into nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield prefix+(k,)
            yield from all_paths(v, prefix+(k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield prefix+(i,)
            yield from all_paths(v, prefix+(i,))

def get_at(obj, path):
    cur = obj
    for k in path:
        cur = cur[k]
    return cur

def set_at(obj, path, val):
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = val

def del_at(obj, path):
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    if isinstance(cur, list):
        del cur[path[-1]]
    else:
        del cur[path[-1]]

def flip_hex_case(s):
    return "".join(c.upper() if c.islower() else c.lower() for c in s)

# signature malleability helpers for ed25519
ED25519_L = 2**252 + 27742317777372353535851937790883648493

def sig_variants(sig_hex):
    out = []
    try:
        raw = bytes.fromhex(sig_hex)
    except Exception:
        return out
    if len(raw) == 64:
        R = raw[:32]; S = int.from_bytes(raw[32:], "little")
        # S + L malleability
        S2 = (S + ED25519_L) % (2**256)
        out.append((R + S2.to_bytes(32, "little")).hex())
        # flip high bit of last byte
        b = bytearray(raw); b[-1] ^= 0x80
        out.append(bytes(b).hex())
        # flip a random byte
        b2 = bytearray(raw); b2[random.randrange(64)] ^= 0x01
        out.append(bytes(b2).hex())
    out.append(sig_hex.upper())
    out.append(flip_hex_case(sig_hex))
    out.append("00"+sig_hex[2:])
    out.append(sig_hex+"00")
    out.append(sig_hex[:-2])
    return out

def gen_mutations(n_target=20000):
    """Yield (kind, submission_dict)."""
    base = copy.deepcopy(ISS)
    # enumerate leaf paths in each of proposal/trace/auth
    trials = 0
    # 1) single field replacement with type-confused / boundary / unicode values
    for part in ("proposal", "trace", "auth"):
        paths = list(all_paths(base[part]))
        for path in paths:
            for val in TYPE_CONFUSE + NUM_BOUND + UNICODE:
                sub = copy.deepcopy(base)
                try:
                    set_at(sub[part], path, copy.deepcopy(val))
                except Exception:
                    continue
                yield ("replace:%s:%s" % (part, ".".join(map(str,path))), sub)
                trials += 1
    # 2) drop each key
    for part in ("proposal", "trace", "auth"):
        for path in list(all_paths(base[part])):
            sub = copy.deepcopy(base)
            try:
                del_at(sub[part], path)
            except Exception:
                continue
            yield ("drop:%s:%s" % (part, ".".join(map(str,path))), sub)
    # 3) extra keys
    for part in ("proposal", "trace", "auth"):
        for _ in range(50):
            sub = copy.deepcopy(base)
            sub[part][rand_str()] = copy.deepcopy(random.choice(TYPE_CONFUSE))
            yield ("extra:%s" % part, sub)
    # 4) swap whole parts between issued/refused/expired
    envs = {"ISS": ISS, "REF": REF, "EXP": EXP}
    for pn, pp in envs.items():
        for tn, tp in envs.items():
            for an, ap in envs.items():
                sub = {"proposal": copy.deepcopy(pp["proposal"]),
                       "trace": copy.deepcopy(tp["trace"]),
                       "auth": copy.deepcopy(ap["auth"])}
                yield ("swap:P%s.T%s.A%s" % (pn,tn,an), sub)
    # 5) swap individual auth fields from REFUSED/EXPIRED into ISSUED auth
    for src_name, src in (("REF", REF), ("EXP", EXP)):
        for k in src["auth"]:
            sub = copy.deepcopy(base)
            sub["auth"][k] = copy.deepcopy(src["auth"][k])
            yield ("authfield:%s.%s" % (src_name, k), sub)
    # 6) signature malleability / hex-format variants
    for var in sig_variants(base["auth"]["signature"]):
        sub = copy.deepcopy(base)
        sub["auth"]["signature"] = var
        yield ("sig", sub)
    # 7) decision variants
    for dv in ["authorize","AUTHORIZE","refuse","flag","", "Authorize", None, 1]:
        sub = copy.deepcopy(base); sub["auth"]["decision"] = dv
        yield ("decision", sub)
    # 8) nonce/determination reuse & whitespace
    for k in ("nonce","determination_id"):
        for suff in ["", " ", "\t", "\n", ISS["auth"][k]+" "]:
            sub = copy.deepcopy(base); sub["auth"][k] = ISS["auth"][k]+suff if suff else ISS["auth"][k]
            yield ("noncews:%s"%k, sub)
    # 9) numeric string vs int for issued_at/expires_at/created_at
    for part,field in (("auth","issued_at"),("auth","expires_at"),("proposal","created_at"),("trace","created_at")):
        for val in ["2000000000", 2000000000.0, 2000000000, True, 2**63, -1, 0, 1e309]:
            sub = copy.deepcopy(base); sub[part][field] = val
            yield ("numtype:%s.%s"%(part,field), sub)
    # 10) random combined multi-field fuzz to reach the target count
    all_leaf = [("proposal",p) for p in all_paths(base["proposal"])] + \
               [("trace",p) for p in all_paths(base["trace"])] + \
               [("auth",p) for p in all_paths(base["auth"])]
    while trials < n_target:
        sub = copy.deepcopy(base)
        k = random.randint(1,4)
        for _ in range(k):
            part, path = random.choice(all_leaf)
            val = random.choice(TYPE_CONFUSE+NUM_BOUND+UNICODE)
            try: set_at(sub[part], path, copy.deepcopy(val))
            except Exception: pass
        yield ("randmulti", sub)
        trials += 1

# ---------- run ----------
counts = {}
kind_counts = {}
findings = []
accept_log = []
n = 0
for kind, sub in gen_mutations(20000):
    n += 1
    identical = (json.dumps(sub, sort_keys=True, default=repr) == json.dumps(ISS, sort_keys=True, default=repr))
    o, r, e, before, after = run_submission(sub)
    counts[o] = counts.get(o, 0) + 1
    kc = kind.split(":")[0]
    kind_counts.setdefault(kc, {}).setdefault(o, 0)
    kind_counts[kc][o] += 1
    interesting = False; why = ""
    if o == "ACCEPT":
        accept_log.append({"kind": kind, "identical_strict": identical})
        rec = e._records[-1] if e._records else None
        if len(e._records) != 1 or rec.sequence != 1:
            interesting = True; why += " | unexpected record count/sequence"
        rd = rec.resulting_digest if rec else None
        if not identical:
            interesting = True; why = "ACCEPT non-identical submission (same_result=%s)" % (rd == ISSUED_RESULT)
        if rd != ISSUED_RESULT:
            interesting = True; why += " | different resulting_digest %s" % (rd[:16] if rd else None)
        if not e.verify_history():
            interesting = True; why += " | verify_history FALSE after accept"
    elif o == "FAULT":
        interesting = True; why = "non-Refusal exception (crash-not-refuse)"
    elif o == "BUILD_ERROR":
        interesting = True; why = "adapter builder raised non-refusal"
    # atomicity: any state/records/nonce change on a non-accept
    if o != "ACCEPT":
        d = common.diff_snapshot(before, after)
        if d:
            interesting = True; why += " | STATE MUTATED ON NON-ACCEPT: %s" % list(d.keys())
    if not before["verify_history"] or (o!="ACCEPT" and not after["verify_history"]):
        interesting = True; why += " | verify_history broken"
    if interesting:
        extra = {}
        if o == "ACCEPT" and not identical:
            extra["diff"] = {pt: {k: [ISS[pt].get(k, "<absent>"), sub[pt].get(k, "<absent>")] for k in set(ISS[pt])|set(sub[pt]) if ISS[pt].get(k, "<absent>") != sub[pt].get(k, "<absent>")} for pt in ("proposal","trace","auth")}
        findings.append({**extra, "n": n, "kind": kind, "outcome": o, "reason": r,
                         "why": why.strip(" |"), "identical": identical})

summary_ident = None
summary = {"accepts_total": len(accept_log), "accepts_strict_identical": sum(a["identical_strict"] for a in accept_log),
           "accept_kinds": sorted({a["kind"] for a in accept_log}), "seed": SEED, "total_trials": n, "counts": counts,
           "kind_counts": kind_counts, "num_findings": len(findings),
           "findings": findings[:500]}
json.dump(summary, open("/workspace/lab5/results/fuzz_findings_v113.json","w"), indent=2, default=str)
print("total trials:", n)
print("accepts: total=%d strict-identical=%d non-identical=%d" % (len(accept_log), sum(a["identical_strict"] for a in accept_log), sum(not a["identical_strict"] for a in accept_log)))
print("counts:", json.dumps(counts))
print("distinct FAULT reasons:")
faults = {}
for f in findings:
    if f["outcome"] in ("FAULT","BUILD_ERROR"):
        faults[f["reason"]] = faults.get(f["reason"],0)+1
for k,v in sorted(faults.items(), key=lambda x:-x[1]):
    print("  %5d  %s" % (v, k))
accepts_nonident = [f for f in findings if f["outcome"]=="ACCEPT"]
print("ACCEPT findings (non-identical / anomalous):", len(accepts_nonident))
for f in accepts_nonident[:20]:
    print("  ", f["kind"], f["why"])
print("saved fuzz_findings.json (findings capped at 500 in file), num_findings=", len(findings))

# ---------- Phase 2b: post-commit replay sweep (legit already committed) ----------
random.seed(SEED + 1)
post_counts = {}
post_findings = []
gen2 = list(itertools.islice(gen_mutations(20000), 0, None))
sample = random.sample(gen2, 3000)
for kind, sub in sample:
    e, clock = make_engine()
    p0, t0, a0 = (H.build_proposal(m, ISS["proposal"]), H.build_trace(m, ISS["trace"]), H.build_auth(m, ISS["auth"]))
    e.commit(p0, t0, a0)
    before = common.deep_snapshot(m, e)
    try:
        p = H.build_proposal(m, sub["proposal"]); t = H.build_trace(m, sub.get("trace")); a = H.build_auth(m, sub.get("auth"))
    except (H.ParseRefusal, H.AdapterRefusal):
        post_counts["ADAPTER_REFUSE"] = post_counts.get("ADAPTER_REFUSE", 0) + 1; continue
    try:
        e.commit(p, t, a); o = "ACCEPT"
    except (m.Refusal, m.TraceError): o = "REFUSE"
    except Exception as ex: o = "FAULT"
    post_counts[o] = post_counts.get(o, 0) + 1
    after = common.deep_snapshot(m, e)
    if o == "ACCEPT" or (o != "ACCEPT" and common.diff_snapshot(before, after)) or not after["verify_history"]:
        post_findings.append({"kind": kind, "outcome": o, "diff": list(common.diff_snapshot(before, after))})
# exact replay of the legit submission (also in the sample space, but explicit)
e, clock = make_engine()
p0, t0, a0 = (H.build_proposal(m, ISS["proposal"]), H.build_trace(m, ISS["trace"]), H.build_auth(m, ISS["auth"]))
e.commit(p0, t0, a0)
try:
    e.commit(p0, t0, a0); exact_replay = "ACCEPT"
except Exception as ex:
    exact_replay = "%s: %s" % (type(ex).__name__, ex)
print("post-commit sweep (3000 sampled mutations after legit commit):", json.dumps(post_counts))
print("post-commit anomalies:", len(post_findings))
print("exact replay after legit:", exact_replay)

# FAULT breakdown by field (first-phase findings)
by_field = {}
for f in findings:
    if f["outcome"] == "FAULT" and f["kind"].startswith(("replace:", "numtype:")):
        key = f["kind"].split(":", 1)[1] + " -> " + f["reason"].split(":")[0] + ":" + f["reason"].split(":")[1][:50]
        by_field[key] = by_field.get(key, 0) + 1
summary["post_commit_counts"] = post_counts
summary["post_commit_findings"] = post_findings
summary["exact_replay_after_legit"] = exact_replay
summary["fault_by_field"] = by_field
json.dump(summary, open("/workspace/lab5/results/fuzz_findings_v113.json", "w"), indent=2, default=str)
print("FAULT by field (single-field replacement):")
for k, v in sorted(by_field.items()):
    print("  %4d  %s" % (v, k))
