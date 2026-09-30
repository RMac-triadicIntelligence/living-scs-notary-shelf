"""lscs_harness.py - runs a JSON attack file against the REAL v1.1.4 CommitEngine (lab5 copy of harness v0.2.1).

Channel: attacks are literal JSON, parsed strictly, never executed. A thin
adapter converts JSON into the package's own dataclasses using their own
constructors. The adapter adds NO policy checks; if it can't build an object it
reports ADAPTER_REFUSE separately so engine refusals are never inflated.

    python3 lscs_harness.py attacks.json            # real engine
    python3 lscs_harness.py attacks.json --mutants  # + kill score vs the package's own M1-M12
"""
import copy, hashlib, importlib.util, json, os, sys, tempfile, time, uuid, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.join(HERE, "living_scs_v114")
T0 = 2_000_000_000
INITIAL_STATE = {"maturity": "juvenile", "personality": {"tone": "humble"},
                 "organs": {}, "policy": {"egress": "deny"}}
ISSUED_MUT = {"op": "set", "path": ["personality", "motto"], "value": "dwell first"}
REFUSED_MUT = {"op": "set_maturity", "value": "mature"}           # the target
EXPIRED_MUT = {"op": "set", "path": ["personality", "tone"], "value": "curious"}
MAX_FILE = 2_000_000


# ---------------------------------------------------------------- loading
def load_module(core_path, name):
    spec = importlib.util.spec_from_file_location(name, core_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class ParseRefusal(Exception):
    pass


class AdapterRefusal(Exception):
    pass


def strict_loads(text):
    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                raise ParseRefusal("duplicate key %r" % k)
            d[k] = v
        return d

    def const(c):
        raise ParseRefusal("non-finite number %s" % c)
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=const)
    except ParseRefusal:
        raise
    except (ValueError, RecursionError) as e:
        raise ParseRefusal("%s: %s" % (type(e).__name__, str(e)[:80]))


# ---------------------------------------------------------------- session
def evidence(m, eid):
    return [m.EvidenceItem(eid, "sensor://organism/log/" + eid, T0 - 50, "drift_detector", "1.0", {"score": 0.91})]


def interp(m):
    return m.Interpretation("basin_consolidation", "1.3", {"read": "stable"}, 0.9, 0.8, 0.7, 0.9)


def new_session(m):
    priv = m.Ed25519PrivateKey.generate()
    auth_id = "minato-" + uuid.uuid4().hex[:8]
    signer = m.MinatoAuthority(auth_id, priv)
    pub = signer.public_key_bytes()
    clock = m.TrustedClock(T0)
    org = "organism-" + uuid.uuid4().hex[:8]
    eng = m.CommitEngine(org, INITIAL_STATE, m.MinatoAuthority.verifier_only(auth_id, priv.public_key()),
                         clock, expected_authority_id=auth_id, expected_public_key=pub)

    def mint(pid, mut, decision, issued_at, expires_at):
        p = eng.proposal_for_mutation(proposal_id=pid, mutation_type=mut["op"], mutation=mut,
                                      evidence=evidence(m, "ev-" + pid), interpretation=interp(m),
                                      created_at=issued_at)
        t = m.make_trace(p, trace_id="trace-" + pid, created_at=issued_at)
        a = signer.issue(t, p, decision=decision, determination_id="det-" + pid,
                         nonce=os.urandom(16).hex(), issued_at=issued_at, expires_at=expires_at)
        return {"proposal": p, "trace": t, "auth": a}

    material = {
        "ISSUED": mint("p-issued", ISSUED_MUT, m.Decision.AUTHORIZE, T0, T0 + 300),
        "REFUSED": mint("p-target", REFUSED_MUT, m.Decision.REFUSE, T0, T0 + 300),
        "EXPIRED": mint("p-old", EXPIRED_MUT, m.Decision.AUTHORIZE, T0 - 1000, T0 - 10),
    }
    del signer, priv                                   # authority leaves the room
    return eng, material, pub.hex(), auth_id, org


# ---------------------------------------------------------------- JSON <-> objects
def to_json(m, obj):
    if isinstance(obj, m.MutationProposal):
        d = obj.unsigned_body()
        d["evidence"] = [dict(e) for e in d["evidence"]]
        return copy.deepcopy(d)
    if isinstance(obj, m.ConsolidationTrace):
        d = obj.body(); d["evidence_ids"] = list(d["evidence_ids"]); return d
    if isinstance(obj, m.AuthorizationEnvelope):
        d = obj.signed_body(); d["signature"] = obj.signature; return d
    raise TypeError(type(obj))


def _fields(cls):
    return list(cls.__dataclass_fields__)


def _build(cls, d, conv=None):
    if type(d) is not dict:
        raise AdapterRefusal("%s must be an object" % cls.__name__)
    extra = set(d) - set(_fields(cls))
    if extra:
        raise AdapterRefusal("%s unknown fields %s" % (cls.__name__, sorted(extra)))
    d = dict(d)
    for k, f in (conv or {}).items():
        if k in d:
            d[k] = f(d[k])
    try:
        return cls(**d)
    except TypeError as e:
        raise AdapterRefusal("%s: %s" % (cls.__name__, e))


def build_proposal(m, d):
    def ev(lst):
        if type(lst) is not list:
            raise AdapterRefusal("evidence must be a list")
        return tuple(_build(m.EvidenceItem, x) for x in lst)
    return _build(m.MutationProposal, d, {"evidence": ev,
                                          "interpretation": lambda x: _build(m.Interpretation, x)})


def _enum(E):
    def f(v):
        try:
            return E(v)
        except (ValueError, TypeError):
            raise AdapterRefusal("bad %s value" % E.__name__)
    return f


def build_trace(m, d):
    if d is None:
        return None
    return _build(m.ConsolidationTrace, d, {"status": _enum(m.ProposalStatus),
                                            "evidence_ids": lambda x: tuple(x) if type(x) is list else x})


def build_auth(m, d):
    if d is None:
        return None
    return _build(m.AuthorizationEnvelope, d, {"decision": _enum(m.Decision)})


def build_artifact(m, d):
    if d is None:
        return None
    if type(d) is not dict or set(d) != {"name", "content_hex", "use_category", "declared_digest", "source_uri"}:
        raise AdapterRefusal("artifact needs name, content_hex, use_category, declared_digest, source_uri")
    try:
        content = bytes.fromhex(d["content_hex"])
    except (TypeError, ValueError):
        raise AdapterRefusal("content_hex not hex")
    return m.OrganArtifact(d["name"], content, d["use_category"], d["declared_digest"], d["source_uri"])


# ---------------------------------------------------------------- placeholders & helpers
def context(m, eng, material, pub, auth_id, org):
    ctx = {"$STATE_DIGEST": eng.state_digest, "$NOW": T0, "$PUBKEY_HEX": pub,
           "$AUTHORITY_ID": auth_id, "$ORGANISM_ID": org,
           "$POLICY_VERSION": m.POLICY_VERSION, "$TRACE_SCHEMA": m.TRACE_SCHEMA,
           "$STATE": eng.state}
    for name, mat in material.items():
        for part in ("proposal", "trace", "auth"):
            ctx["$%s.%s" % (name, part)] = to_json(m, mat[part])
    return ctx


RESOLVE_DEPTH = 200   # below this, subtrees pass through untouched to the engine


def resolve(m, eng, x, ctx, depth=0):
    if depth > RESOLVE_DEPTH:
        return x
    if isinstance(x, str):
        return copy.deepcopy(ctx[x]) if x in ctx else x
    if isinstance(x, list):
        return [resolve(m, eng, i, ctx, depth + 1) for i in x]
    if isinstance(x, dict):
        if len(x) == 1:
            (op, arg), = x.items()
            if op.startswith("$") and op not in ctx:
                a = resolve(m, eng, arg, ctx, depth + 1)
                try:
                    if op == "$merge":
                        base, over = a
                        out = dict(base); out.update(over); return out
                    if op == "$delete":
                        base, keys = a
                        return {k: v for k, v in base.items() if k not in keys}
                    if op == "$sha256":
                        return m.sha256_hex(a)
                    if op == "$expected_digest":
                        return eng.expected_digest(a)
                    if op == "$proposal_digest":
                        return build_proposal(m, a).digest()
                    if op == "$evidence_digest":
                        return build_proposal(m, a).evidence_digest()
                    if op == "$make_trace":
                        return to_json(m, m.make_trace(build_proposal(m, a), trace_id="trace-attacker"))
                    if op == "$trace_digest":
                        return build_trace(m, a).digest()
                except AdapterRefusal:
                    raise
                except Exception as e:
                    raise AdapterRefusal("helper %s: %s: %s" % (op, type(e).__name__, str(e)[:80]))
                raise AdapterRefusal("unknown helper %s" % op)
        return {k: resolve(m, eng, v, ctx, depth + 1) for k, v in x.items()}
    return x


def raw_sub(text, ctx):
    for k in sorted(ctx, key=len, reverse=True):
        v = ctx[k]
        if isinstance(v, (str, int)):
            text = text.replace(k, str(v))
    return text


# ---------------------------------------------------------------- run
def run_session(m, sess):
    eng, material, pub, auth_id, org = new_session(m)
    issued_result = material["ISSUED"]["proposal"].expected_result_digest
    rows, breaches = [], []
    for att in sess.get("attempts", []):
        ctx = context(m, eng, material, pub, auth_id, org)
        outcome, reason = None, ""
        try:
            sub = strict_loads(raw_sub(att["raw_json"], ctx)) if "raw_json" in att else att.get("submission")
            sub = resolve(m, eng, sub, ctx)
            if type(sub) is not dict or not {"proposal"} <= set(sub) or set(sub) - {"proposal", "trace", "auth", "artifact", "reason"}:
                raise AdapterRefusal("submission needs proposal[, trace, auth, artifact, reason]")
            p = build_proposal(m, sub["proposal"])
            t = build_trace(m, sub.get("trace"))
            a = build_auth(m, sub.get("auth"))
            art = build_artifact(m, sub.get("artifact"))
            reason_txt = sub.get("reason", "authorized mutation")
            if type(reason_txt) is not str:
                raise AdapterRefusal("reason must be a string")
        except (ParseRefusal, AdapterRefusal) as e:
            outcome, reason = "ADAPTER_REFUSE", str(e)
        except Exception as e:                   # the judge failed, not the engine
            outcome, reason = "HARNESS_ERROR", "%s: %s" % (type(e).__name__, str(e)[:120])
        if outcome is None:
            before = len(eng.records)
            try:
                eng.commit(p, t, a, reason=reason_txt, artifact=art)
                outcome = "ACCEPT"
            except (m.Refusal, m.TraceError) as e:
                outcome, reason = "REFUSE", "%s: %s" % (type(e).__name__, e)
            except Exception as e:
                outcome, reason = "FAULT", "%s: %s" % (type(e).__name__, str(e)[:120])
            if outcome == "ACCEPT":
                rec = eng.records[-1]
                if rec.resulting_digest != issued_result or rec.sequence != 1:
                    breaches.append(("B2_unauthorized_transition", att.get("id"), rec.resulting_digest[:16]))
                if len(eng.records) > 1:
                    breaches.append(("B3_extra_commit", att.get("id"), len(eng.records)))
        exp = att.get("expect")
        rows.append({"id": att.get("id"), "intent": att.get("intent", ""), "outcome": outcome,
                     "reason": reason, "expect": exp, "matches_expect": exp is None or exp == outcome})
    st = eng.state
    if st.get("maturity") != "juvenile":
        breaches.append(("B1_self_promoted_maturity", None, st.get("maturity")))
    if st.get("organs"):
        breaches.append(("B1_organ_installed", None, sorted(st["organs"])))
    if st.get("policy") != INITIAL_STATE["policy"]:
        breaches.append(("B1_policy_changed", None, st.get("policy")))
    if not eng.verify_history():
        breaches.append(("B4_history_broken", None, None))
    return {"name": sess.get("name"), "rows": rows, "breaches": breaches,
            "accepted": len(eng.records), "final_state": st,
            "faults": sum(r["outcome"] == "FAULT" for r in rows),
            "harness_errors": sum(r["outcome"] == "HARNESS_ERROR" for r in rows)}


def run_file(data, m):
    return [run_session(m, s) for s in data.get("sessions", [])]


def real_module():
    return load_module(os.path.join(PKG_DIR, "core.py"), "lscs_real_%s" % uuid.uuid4().hex[:6])


def package_mutants():
    """The package's own M1-M12, applied to disposable copies of core.py."""
    ns = {}
    src = open(os.path.join(HERE, "_pkg_check_mutations.py")).read()
    start = src.index("MUTATIONS = (")
    end = src.index("\n\n\ndef hashes")
    exec(src[start:end], ns)                              # the tuple literal only
    base = open(os.path.join(PKG_DIR, "core.py"), encoding="utf-8").read()
    for mid, target, old, new, _ in ns["MUTATIONS"]:
        assert base.count(old) == 1, mid
        d = tempfile.mkdtemp(prefix="lscs-%s-" % mid)
        p = os.path.join(d, "core.py")
        open(p, "w", encoding="utf-8").write(base.replace(old, new, 1))
        yield mid, target, load_module(p, "lscs_%s_%s" % (mid, uuid.uuid4().hex[:6]))
        shutil.rmtree(d, ignore_errors=True)


def sha_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    path = sys.argv[1]
    if os.path.getsize(path) > MAX_FILE:
        sys.exit("attack file too large")
    data = strict_loads(open(path, encoding="utf-8").read())
    results = run_file(data, real_module())
    breaches = [b for r in results for b in r["breaches"]]
    faults = sum(r["faults"] for r in results)
    herr = sum(r["harness_errors"] for r in results)
    print("=" * 70)
    print("LIVING SCS v1.1.4 DOOR CHALLENGE  attacker=%s" % data.get("attacker", "?"))
    print("=" * 70)
    for r in results:
        print("\n[session] %s  accepted=%d  maturity=%s" % (r["name"], r["accepted"], r["final_state"].get("maturity")))
        for row in r["rows"]:
            flag = "" if row["matches_expect"] else "   <-- expect=%s" % row["expect"]
            print("  %-15s %-26s %s%s" % (row["outcome"], (row["id"] or "")[:26], row["reason"][:70], flag))
        for b in r["breaches"]:
            print("  !!! BREACH %s attempt=%s %s" % b)
    kill = None
    if "--mutants" in sys.argv:
        kill = {}
        print("\nKill score vs the package's own mutations (would this corpus breach a weakened engine?)")
        for mid, target, mm in package_mutants():
            k = any(r["breaches"] for r in run_file(data, mm))
            kill[mid] = k
            print("  %-4s %-48s %s" % (mid, target[:48], "KILLED" if k else "survived"))
        print("  total: %d/%d" % (sum(kill.values()), len(kill)))
    status = "RED" if breaches else "GREEN"
    print("\nTARGET STATUS: %s  (breaches=%d, faults=%d, harness errors=%d)" % (status, len(breaches), faults, herr))
    receipt = {"attacker": data.get("attacker"), "notes": data.get("notes"),
               "attack_file_sha256": sha_file(path),
               "core_py_sha256": sha_file(os.path.join(PKG_DIR, "core.py")),
               "harness_sha256": sha_file(os.path.abspath(__file__)),
               "target_status": status, "breaches": [list(map(str, b)) for b in breaches],
               "faults": faults, "harness_errors": herr, "mutant_kill": kill,
               "sessions": [{k: r[k] for k in ("name", "accepted", "rows")} for r in results],
               "run_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    os.makedirs(os.path.join(HERE, "receipts"), exist_ok=True)
    out = os.path.join(HERE, "receipts", "v114_receipt_%s.json" % receipt["attack_file_sha256"][:12])
    json.dump(receipt, open(out, "w"), indent=2, default=str)
    print("receipt:", out)
    sys.exit(1 if breaches else 0)


if __name__ == "__main__":
    main()
