"""Targeted tests for the v1.1.4 hardening fixes (run: python3 -m unittest -v tests/test_v114_hardening.py)."""
import copy, hashlib, importlib, importlib.util, math, os, sys, threading, unittest
from dataclasses import replace, asdict

LAB5 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(LAB5, "v114"))
import living_scs_v114 as L
from living_scs_v114 import core as C
from living_scs_v114 import fixtures as F

_spec = importlib.util.spec_from_file_location("v113_ref_core", os.path.join(LAB5, "v113_ref", "living_scs_v113", "core.py"))
V113 = importlib.util.module_from_spec(_spec); sys.modules["v113_ref_core"] = V113; _spec.loader.exec_module(V113)


def signed(eng, signer, mutation, *, pid="p-x", nonce="n-x", det="d-x", evidence=None, mtype="personality_drift"):
    prop = eng.proposal_for_mutation(proposal_id=pid, mutation_type=mtype, mutation=mutation,
                                     evidence=evidence or F.evidence(), interpretation=F.interpretation(), created_at=F.NOW)
    trace = C.make_trace(prop, trace_id="t-" + pid, created_at=F.NOW)
    auth = signer.issue(trace, prop, decision=C.Decision.AUTHORIZE, determination_id=det, nonce=nonce,
                        issued_at=F.NOW, expires_at=F.NOW + 600)
    return prop, trace, auth


def snap(eng):
    return (copy.deepcopy(eng._state), [asdict(r) for r in eng._records], sorted(eng._states), dict(eng._parents),
            set(eng._used_nonces), set(eng._used_determinations), eng._commit_in_progress)


class Fix1ReentrancyAtomicity(unittest.TestCase):
    def test_reentrant_same_auth_refused_single_record(self):
        box = {}
        def hook(rec, st):
            try:
                box["eng"].commit(box["p"], box["t"], box["a"], reason="inner")
            except C.Refusal as e:
                box["inner"] = str(e)
        signer, clock, eng = F.engine(persist_hook=hook)
        p, t, a = signed(eng, signer, F.mutation())
        box.update(eng=eng, p=p, t=t, a=a)
        eng.commit(p, t, a)
        self.assertIn("re-entrant commit refused", box["inner"])
        self.assertEqual([r.sequence for r in eng._records], [1])
        self.assertTrue(eng.verify_history())
        self.assertFalse(eng._commit_in_progress)

    def test_reentrant_different_valid_auth_and_restore_refused(self):
        signer, clock, eng = F.engine()
        p1, t1, a1 = signed(eng, signer, F.mutation(0.40), pid="p1", nonce="n1", det="d1")
        other = signed(eng, signer, {"op": "restore_state", "snapshot": F.initial_state()}, pid="p2", nonce="n2", det="d2", mtype="restore_state")
        seen = []
        def hook(rec, st):
            for args in (other,):
                try:
                    eng.commit(*args); seen.append("ACCEPTED")
                except C.Refusal as e:
                    seen.append(str(e))
        eng._persist_hook = hook
        eng.commit(p1, t1, a1)
        self.assertEqual(len(seen), 1); self.assertIn("re-entrant commit refused", seen[0])
        self.assertEqual(len(eng._records), 1)

    def test_hook_sees_precommit_state_with_nonce_reserved_and_copies(self):
        obs = {}
        def hook(rec, st):
            obs["records"] = len(eng._records)
            obs["state_motto_before"] = eng._state["personality"].get("verbosity")
            obs["nonce_reserved"] = "nonce-1" in eng._used_nonces
            obs["rec"] = rec
            st["maturity"] = "mature"                       # mutate the hook's copy
            object.__setattr__(rec, "reason", "TAMPERED")   # mutate the hook's record copy
        signer, clock, eng = F.engine(persist_hook=hook)
        p, t, a = signed(eng, signer, F.mutation(), nonce="nonce-1")
        eng.commit(p, t, a)
        self.assertEqual(obs["records"], 0)
        self.assertEqual(obs["state_motto_before"], 0.50)
        self.assertTrue(obs["nonce_reserved"])
        self.assertIsNot(obs["rec"], eng._records[0])
        self.assertEqual(eng._state["maturity"], "juvenile")
        self.assertEqual(eng._records[0].reason, "authorized mutation")
        self.assertTrue(eng.verify_history())

    def test_hook_failure_changes_nothing_and_releases_reservation(self):
        calls = {"n": 0}
        def hook(rec, st):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("disk full")
        signer, clock, eng = F.engine(persist_hook=hook)
        p, t, a = signed(eng, signer, F.mutation())
        before = snap(eng)
        with self.assertRaises(RuntimeError):          # not wrapped: it is not a pre-commit validation error
            eng.commit(p, t, a)
        self.assertEqual(snap(eng), before)
        eng.commit(p, t, a)                              # same authorization succeeds once the hook works
        self.assertEqual(len(eng._records), 1)
        with self.assertRaises(C.Refusal):
            eng.commit(p, t, a)

    def test_threads_same_auth_exactly_one_commit(self):
        signer, clock, eng = F.engine()
        p, t, a = signed(eng, signer, F.mutation())
        results = []
        def go():
            try:
                eng.commit(p, t, a); results.append("ACCEPT")
            except C.Refusal:
                results.append("REFUSE")
        ts = [threading.Thread(target=go) for _ in range(16)]
        [x.start() for x in ts]; [x.join() for x in ts]
        self.assertEqual(results.count("ACCEPT"), 1); self.assertEqual(len(eng._records), 1)


class Fix2KeyedHistory(unittest.TestCase):
    def _forged(self, rec, aid):
        return {"sequence": 2, "event": "mutation_committed", "trace_digest": "a" * 64, "proposal_digest": "b" * 64,
                "predecessor_digest": rec.resulting_digest, "resulting_digest": "c" * 64, "authorization_id": "forged",
                "authority_id": aid, "reason": "forged", "timestamp": F.NOW, "previous_record_hash": rec.record_hash}

    def _keyed_engine(self, key):
        signer, verifier = F.authority_pair()
        clock = C.TrustedClock(F.NOW)
        eng = C.CommitEngine("organism-alpha", F.initial_state(), verifier, clock, expected_authority_id="owner-root-1",
                             expected_public_key=C.deterministic_test_private_key().public_key().public_bytes_raw(),
                             history_key=key)
        return signer, eng

    def test_keyed_detects_forged_append_and_tamper(self):
        signer, eng = self._keyed_engine(b"K" * 32)
        eng.commit(*signed(eng, signer, F.mutation()))
        self.assertTrue(eng.verify_history())
        rec = eng._records[0]
        ev = self._forged(rec, "owner-root-1")
        eng._records.append(C.CommitRecord(**ev, record_hash=C.sha256_hex(ev)))
        self.assertFalse(eng.verify_history())
        eng._records.pop(); self.assertTrue(eng.verify_history())
        object.__setattr__(eng._records[0], "reason", "rewritten")
        self.assertFalse(eng.verify_history())
        self.assertTrue(C.verify_record_chain([], history_key=b"K" * 32))

    def test_unkeyed_is_byte_compatible_with_v113(self):
        # same deterministic key, same clock, same inputs -> identical record hash in v1.1.3 and v1.1.4 (unkeyed)
        out = []
        for mod in (V113, C):
            signer = mod.MinatoAuthority("owner-root-1", mod.deterministic_test_private_key())
            eng = mod.CommitEngine("organism-alpha", F.initial_state(), mod.MinatoAuthority.verifier_only("owner-root-1", signer.public_key),
                                   mod.TrustedClock(F.NOW), expected_authority_id="owner-root-1",
                                   expected_public_key=mod.deterministic_test_private_key().public_key().public_bytes_raw())
            ev = (mod.EvidenceItem("e-0", "memory://episode/0", F.NOW - 10, "rule_counter", "1.0", {"count": 1}),)
            it = mod.Interpretation("fenced-enumerated-reader", "0.3", {"read_as": "x"}, 0.9, 0.7, 0.5, 0.8)
            prop = eng.proposal_for_mutation(proposal_id="p", mutation_type="personality_drift", mutation=F.mutation(),
                                             evidence=ev, interpretation=it, created_at=F.NOW)
            tr = mod.make_trace(prop, trace_id="t", created_at=F.NOW)
            au = signer.issue(tr, prop, decision=mod.Decision.AUTHORIZE, determination_id="d", nonce="n", issued_at=F.NOW, expires_at=F.NOW + 60)
            eng.commit(prop, tr, au)
            r = eng.records[0]
            out.append((prop.digest(), tr.digest(), au.signature, r.record_hash, eng.state_digest))
            body = asdict(r); body.pop("record_hash")
            self.assertEqual(r.record_hash, hashlib.sha256(mod.canonical_json(body)).hexdigest())
        self.assertEqual(out[0], out[1])

    def test_keyed_hash_differs_and_key_validation(self):
        signer, eng = self._keyed_engine(b"K" * 32)
        eng.commit(*signed(eng, signer, F.mutation()))
        body = asdict(eng._records[0]); claimed = body.pop("record_hash")
        self.assertNotEqual(claimed, C.sha256_hex(body))
        self.assertTrue(C.is_sha256(claimed))
        for bad in (b"short", "a string key of enough length", 12345):
            with self.assertRaises(C.Refusal):
                self._keyed_engine(bad)


class Fix3RecordCopies(unittest.TestCase):
    def test_public_records_and_snapshot_are_copies(self):
        signer, clock, eng = F.engine()
        eng.commit(*signed(eng, signer, F.mutation()))
        r = eng.records[0]
        self.assertIsNot(r, eng._records[0]); self.assertEqual(r, eng._records[0])
        object.__setattr__(r, "reason", "TAMPERED")
        _, _, recs = eng.history_snapshot()
        self.assertIsNot(recs[0], eng._records[0])
        object.__setattr__(recs[0], "reason", "TAMPERED2")
        self.assertTrue(eng.verify_history())
        self.assertEqual(L.living_ai_bom(eng)["mutationHistory"][0]["reason"], "authorized mutation")


class Fix4StrictSha256(unittest.TestCase):
    def test_strict(self):
        class S(str): pass
        good = hashlib.sha256(b"x").hexdigest()
        self.assertTrue(C.is_sha256(good))
        for bad in (good.upper(), " " + good[1:], good[:-1] + "\n", "0x" + good[2:], "+" + good[1:], good[:31] + "_" + good[32:],
                    S(good), good.encode(), None, 123, good + "0", good[:-1], "g" * 64, "٠" * 64):
            self.assertFalse(C.is_sha256(bad), repr(bad))


class Fix5InputValidation(unittest.TestCase):
    def setUp(self):
        self.signer, self.clock, self.eng = F.engine()
        self.p, self.t, self.a = signed(self.eng, self.signer, F.mutation())

    def refuse(self, p=None, t=None, a=None, *, reason="authorized mutation", artifact=None, contains="malformed input"):
        before = snap(self.eng)
        with self.assertRaises(C.Refusal) as cm:
            self.eng.commit(p or self.p, t or self.t, a or self.a, reason=reason, artifact=artifact)
        self.assertEqual(snap(self.eng), before)
        if contains:
            self.assertIn(contains, str(cm.exception))
        return str(cm.exception)

    def ev(self, **kw):
        return replace(self.p, evidence=(replace(self.p.evidence[0], **kw),) + self.p.evidence[1:])

    def test_wrong_types_refused(self):
        P, T, A = self.p, self.t, self.a
        cases = [
            dict(p=self.ev(evidence_id=["e-0"])), dict(p=self.ev(detector=7)), dict(p=self.ev(source_uri=12)),
            dict(p=self.ev(observed_at=True)), dict(p=self.ev(observed_at=1.5)), dict(p=self.ev(observed_at="1")),
            dict(p=replace(P, maturity_state=["juvenile"])), dict(p=replace(P, created_at=True)),
            dict(p=replace(P, created_at="1800000000")), dict(p=replace(P, mutation=[1])),
            dict(p=replace(P, evidence="nope")),
            dict(p=replace(P, interpretation=replace(P.interpretation, confidence=True))),
            dict(p=replace(P, interpretation=replace(P.interpretation, salience="0.5"))),
            dict(p=replace(P, interpretation=replace(P.interpretation, confidence=10 ** 400))),
            dict(t=replace(T, created_at="x")), dict(t=replace(T, created_at=False)), dict(t=replace(T, evidence_ids=5)),
            dict(t=replace(T, evidence_ids=[1, 2])), dict(t=replace(T, status="awaiting_external_authorization")),
            dict(a=replace(A, signature=123)), dict(a=replace(A, signature="zz" * 64)), dict(a=replace(A, signature=A.signature[:-2])),
            dict(a=replace(A, signature=" " + A.signature[1:])), dict(a=replace(A, issued_at=True)),
            dict(a=replace(A, expires_at=float(F.NOW + 600))), dict(a=replace(A, decision="authorize")),
            dict(a=replace(A, nonce=["n"])), dict(p="not a proposal"), dict(t=object()), dict(a={"signature": "x"}),
        ]
        for kw in cases:
            with self.subTest(kw=list(kw)):
                self.refuse(**kw)
        self.refuse(reason=5)

    def test_numeric_bounds(self):
        for bad in (math.inf, -math.inf, math.nan, 2 ** 53 + 1, -(2 ** 53) - 1, 10 ** 5000):
            with self.subTest(bad=type(bad).__name__ + ("<huge>" if isinstance(bad, int) and bad > 2 ** 60 else repr(bad))[:30]):
                self.refuse(p=self.ev(value={"x": bad}))
        self.refuse(p=replace(self.p, created_at=2 ** 53 + 1))
        self.refuse(a=replace(self.a, expires_at=2 ** 64))

    def test_surrogates_everywhere(self):
        s = "a\ud800b"
        self.refuse(reason=s)
        self.refuse(p=replace(self.p, proposal_id=s)); self.refuse(p=self.ev(detector=s))
        self.refuse(p=self.ev(value={s: 1})); self.refuse(p=replace(self.p, mutation={**self.p.mutation, "value": s}))
        self.refuse(t=replace(self.t, trace_id=s)); self.refuse(a=replace(self.a, nonce=s))

    def test_depth_limit_boundary_and_cycles(self):
        def nest(n):
            v = 0
            for _ in range(n):
                v = [v]
            return v
        self.refuse(p=self.ev(value=nest(65)), contains="nesting deeper than 64")
        self.refuse(p=self.ev(value=nest(100000)), contains="nesting deeper than 64")
        self.refuse(p=replace(self.p, interpretation=replace(self.p.interpretation, output={"o": nest(70)})))
        cyc = []; cyc.append(cyc)
        self.refuse(p=self.ev(value=cyc))
        cycd = {}; cycd["self"] = cycd
        self.refuse(p=replace(self.p, mutation=cycd))
        # exactly 64 nested containers is allowed and, when genuinely signed, commits
        ev64 = (C.EvidenceItem("e-0", "memory://episode/0", F.NOW, "rule_counter", "1.0", nest(64)),)
        p, t, a = signed(self.eng, self.signer, F.mutation(), pid="deep64", nonce="n64", det="d64", evidence=ev64)
        self.eng.commit(p, t, a)
        self.assertEqual(len(self.eng.records), 1)

    def test_non_json_values_and_keys(self):
        self.refuse(p=self.ev(value={1: "int key"}))
        self.refuse(p=self.ev(value=b"bytes"))
        self.refuse(p=self.ev(value={1, 2}))
        self.refuse(p=replace(self.p, mutation={**self.p.mutation, "value": object()}))

    def test_artifact_only_with_install_organ(self):
        self.refuse(artifact=F.organ(), contains="artifact supplied for a non-install_organ operation")

    def test_backstop_wraps_unexpected_precommit_exception(self):
        # A genuinely signed proposal whose set path is an int: every gate passes, then apply_mutation
        # hits list(5) -> TypeError. v1.1.3 raised the raw TypeError; v1.1.4 must refuse.
        bad = C.MutationProposal("bp", "organism-alpha", self.eng.state_digest, "personality_drift",
                                 {"op": "set", "path": 5, "value": 1}, F.evidence(), F.interpretation(),
                                 C.POLICY_VERSION, "juvenile", F.NOW, "e" * 64)
        bt = C.make_trace(bad, trace_id="t-bp", created_at=F.NOW)
        ba = self.signer.issue(bt, bad, decision=C.Decision.AUTHORIZE, determination_id="db", nonce="nb",
                               issued_at=F.NOW, expires_at=F.NOW + 600)
        self.refuse(p=bad, t=bt, a=ba, contains="malformed input: TypeError")
        # (v1.1.3 comparison is done in results/backstop_v113_vs_v114.txt)
        # direct: force an unexpected error in a pre-commit helper
        orig = C.CommitEngine.__dict__["apply_mutation"]  # keep the staticmethod wrapper
        try:
            C.CommitEngine.apply_mutation = staticmethod(lambda s, m: (_ for _ in ()).throw(KeyError("boom")))
            self.refuse(contains="malformed input: KeyError")
        finally:
            C.CommitEngine.apply_mutation = orig

    def test_legit_still_commits_after_refusals(self):
        self.refuse(reason="x\udfff")
        self.refuse(a=replace(self.a, decision="authorize"))
        self.assertEqual(len(self.eng.commit(self.p, self.t, self.a)), 64)
        self.assertEqual(self.eng.state["personality"]["verbosity"], 0.45)
        self.assertTrue(self.eng.verify_history())


class Compatibility(unittest.TestCase):
    def test_v113_minted_material_commits_on_v114(self):
        # authorization minted entirely with v1.1.3 objects, carried as JSON, commits on v1.1.4
        sys.path.insert(0, "/workspace/lab5/v114"); import lscs_harness as H
        signer = V113.MinatoAuthority("owner-root-1", V113.deterministic_test_private_key())
        e3 = V113.CommitEngine("organism-alpha", F.initial_state(), V113.MinatoAuthority.verifier_only("owner-root-1", signer.public_key),
                               V113.TrustedClock(F.NOW), expected_authority_id="owner-root-1",
                               expected_public_key=signer.public_key_bytes())
        prop = e3.proposal_for_mutation(proposal_id="p", mutation_type="personality_drift", mutation=F.mutation(),
                                        evidence=(V113.EvidenceItem("e-0", "memory://x/0", F.NOW, "rule_counter", "1.0", {"c": 1}),),
                                        interpretation=V113.Interpretation("m", "1", {"o": 1}, 0.9, 0.9, 0.5, 0.5), created_at=F.NOW)
        tr = V113.make_trace(prop, trace_id="t", created_at=F.NOW)
        au = signer.issue(tr, prop, decision=V113.Decision.AUTHORIZE, determination_id="d", nonce="n", issued_at=F.NOW, expires_at=F.NOW + 60)
        js = {"proposal": H.to_json(V113, prop), "trace": H.to_json(V113, tr), "auth": H.to_json(V113, au)}
        signer4, clock4, e4 = F.engine()
        r = e4.commit(H.build_proposal(C, js["proposal"]), H.build_trace(C, js["trace"]), H.build_auth(C, js["auth"]))
        self.assertEqual(r, prop.expected_result_digest)

    def test_install_organ_and_restore_paths_still_work(self):
        signer, clock, eng = F.engine(maturity="adolescent")
        org = F.organ()
        mut = {"op": "install_organ", "name": org.name, "digest": org.declared_digest, "use_category": org.use_category, "source_uri": org.source_uri}
        prop = eng.proposal_for_mutation(proposal_id="org", mutation_type="install_organ", mutation=mut, evidence=F.evidence(),
                                         interpretation=F.interpretation(), maturity_state="adolescent", created_at=F.NOW)
        tr = C.make_trace(prop, trace_id="t-org", created_at=F.NOW)
        au = signer.issue(tr, prop, decision=C.Decision.AUTHORIZE, determination_id="do2", nonce="no2", issued_at=F.NOW, expires_at=F.NOW + 600)
        with self.assertRaises(C.Refusal):
            eng.commit(prop, tr, au)                       # no artifact -> refused, as in v1.1.3
        eng.commit(prop, tr, au, artifact=org)
        self.assertIn("search", eng.state["organs"])
        initial = eng.state_at(eng._initial_state_digest)
        rp = eng.proposal_for_mutation(proposal_id="rs", mutation_type="restore_state", mutation={"op": "restore_state", "snapshot": initial},
                                       evidence=F.evidence(), interpretation=F.interpretation(), maturity_state="adolescent", created_at=F.NOW)
        rt = C.make_trace(rp, trace_id="t-rs", created_at=F.NOW)
        ra = signer.issue(rt, rp, decision=C.Decision.AUTHORIZE, determination_id="drs", nonce="nrs", issued_at=F.NOW, expires_at=F.NOW + 600)
        eng.commit(rp, rt, ra)
        self.assertEqual(eng.state_digest, eng._initial_state_digest)
        self.assertEqual([r.sequence for r in eng.records], [1, 2]); self.assertTrue(eng.verify_history())

    def test_public_api_names_preserved(self):
        v113_public = {n for n in dir(V113) if not n.startswith("_")}
        v114_public = {n for n in dir(C) if not n.startswith("_")}
        self.assertEqual(v113_public - v114_public, set())
        print("\n  new public names in v1.1.4:", sorted(v114_public - v113_public - {"hmac", "fields", "logging"}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
