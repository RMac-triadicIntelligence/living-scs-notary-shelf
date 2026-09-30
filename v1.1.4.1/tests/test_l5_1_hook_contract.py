"""L5-1 regression: a persist_hook that writes durably and THEN raises.

The engine rolls back (correct), and a retry of the same authorization commits sequence 1 again.
A naive append-only hook therefore persists sequence 1 twice, so the persisted log diverges from the
engine and fails verify_record_chain. An idempotent upsert-by-sequence hook stays identical to
engine.records, and reconcile_persisted_log() recovers the canonical prefix from a naive log.

Run from /workspace/lab5:  python3 -m unittest -v tests/test_l5_1_hook_contract.py
                      or:  python3 -m unittest discover -s tests -v      (pytest also collects it)
"""
import json, os, sys, unittest
from dataclasses import asdict, replace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "v114"))
from living_scs_v114 import core as C
from living_scs_v114 import fixtures as F

KEY = b"k" * 32


def signed(eng, signer, mutation, *, pid="p-x", nonce="n-x", det="d-x"):
    prop = eng.proposal_for_mutation(proposal_id=pid, mutation_type="personality_drift", mutation=mutation,
                                     evidence=F.evidence(), interpretation=F.interpretation(), created_at=F.NOW)
    trace = C.make_trace(prop, trace_id="t-" + pid, created_at=F.NOW)
    auth = signer.issue(trace, prop, decision=C.Decision.AUTHORIZE, determination_id=det, nonce=nonce,
                        issued_at=F.NOW, expires_at=F.NOW + 600)
    return prop, trace, auth


def make_engine(hook, history_key=None):
    if history_key is None:
        return F.engine(persist_hook=hook)
    signer, verifier = F.authority_pair()
    clock = C.TrustedClock(F.NOW)
    eng = C.CommitEngine("organism-alpha", F.initial_state(), verifier, clock, expected_authority_id="owner-root-1",
                         expected_public_key=C.deterministic_test_private_key().public_key().public_bytes_raw(),
                         persist_hook=hook, history_key=history_key)
    return signer, clock, eng


class NaiveAppendHook:
    """Appends every record it is given (a 'durable write'), and raises AFTER writing on chosen calls."""
    def __init__(self, fail_on=(1,)):
        self.log, self.calls, self.fail_on = [], 0, set(fail_on)

    def __call__(self, record, new_state):
        self.calls += 1
        self.log.append(record)                               # durable write happens first ...
        if self.calls in self.fail_on:
            raise OSError("fsync reported failure after the write")   # ... then the hook raises

    def persisted(self):
        return list(self.log)


class UpsertHook(NaiveAppendHook):
    """Idempotent upsert keyed by sequence: storing seq N overwrites any stored seq N."""
    def __init__(self, fail_on=(1,)):
        super().__init__(fail_on)
        self.store = {}

    def __call__(self, record, new_state):
        self.calls += 1
        self.store[record.sequence] = record
        if self.calls in self.fail_on:
            raise OSError("fsync reported failure after the write")

    def persisted(self):
        return [self.store[k] for k in sorted(self.store)]


def write_raise_retry(hook, *, advance_clock, history_key=None, second_commit=False):
    """Commit once (hook writes, then raises), optionally advance the clock, retry the same auth."""
    signer, clock, eng = make_engine(hook, history_key)
    p, t, a = signed(eng, signer, F.mutation())
    try:
        eng.commit(p, t, a)
        raise AssertionError("first attempt should have raised from the hook")
    except OSError:
        pass
    assert len(eng.records) == 0, "engine must roll back when the hook raises"
    if advance_clock:
        clock.set(F.NOW + 7)
    eng.commit(p, t, a)                                       # retry of the SAME authorization succeeds
    if second_commit:
        p2, t2, a2 = signed(eng, signer, F.mutation(0.40), pid="p-2", nonce="n-2", det="d-2")
        eng.commit(p2, t2, a2)
    return eng, hook.persisted()


def describe(tag, eng, persisted, history_key=None):
    line = ("%s: engine seqs %s verify_history %s | persisted seqs %s verify_record_chain %s | persisted==engine %s"
            % (tag, [r.sequence for r in eng.records], eng.verify_history(), [r.sequence for r in persisted],
               C.verify_record_chain(persisted, history_key=history_key), list(persisted) == list(eng.records)))
    print("\n  " + line, end="")
    return line


class NaiveAppendHookDiverges(unittest.TestCase):
    """BEFORE the contract: reproduces the reviewer's L5-1 divergence."""

    def check(self, advance_clock):
        eng, persisted = write_raise_retry(NaiveAppendHook(), advance_clock=advance_clock)
        describe("naive append-only hook, advance_clock=%s" % advance_clock, eng, persisted)
        self.assertEqual([r.sequence for r in eng.records], [1])
        self.assertTrue(eng.verify_history())
        self.assertEqual([r.sequence for r in persisted], [1, 1])
        self.assertFalse(C.verify_record_chain(persisted))
        self.assertNotEqual(persisted, list(eng.records))
        self.assertEqual(persisted[1], eng.records[0])        # the retry's record is the real one
        return eng, persisted

    def test_fixed_clock(self):
        eng, persisted = self.check(False)
        self.assertEqual(persisted[0], persisted[1])          # same clock -> byte-identical duplicate

    def test_advancing_clock(self):
        eng, persisted = self.check(True)
        self.assertNotEqual(persisted[0].timestamp, persisted[1].timestamp)
        self.assertNotEqual(persisted[0].record_hash, persisted[1].record_hash)
        self.assertNotEqual(persisted[0].record_hash, eng.records[0].record_hash)

    def test_divergence_persists_into_later_commits(self):
        eng, persisted = write_raise_retry(NaiveAppendHook(), advance_clock=True, second_commit=True)
        self.assertEqual([r.sequence for r in eng.records], [1, 2]); self.assertTrue(eng.verify_history())
        self.assertEqual([r.sequence for r in persisted], [1, 1, 2]); self.assertFalse(C.verify_record_chain(persisted))


class UpsertHookStaysConsistent(unittest.TestCase):
    """AFTER the contract: an idempotent upsert-by-sequence hook matches engine.records exactly."""

    def check(self, advance_clock, history_key=None, second_commit=False):
        eng, persisted = write_raise_retry(UpsertHook(), advance_clock=advance_clock, history_key=history_key,
                                           second_commit=second_commit)
        describe("upsert-by-sequence hook, advance_clock=%s keyed=%s" % (advance_clock, history_key is not None),
                 eng, persisted, history_key)
        self.assertEqual(persisted, list(eng.records))
        self.assertTrue(eng.verify_history())
        self.assertTrue(C.verify_record_chain(persisted, history_key=history_key))
        return eng, persisted

    def test_fixed_clock(self):
        self.check(False)

    def test_advancing_clock(self):
        eng, persisted = self.check(True)
        self.assertEqual(persisted[0].timestamp, F.NOW + 7)   # the retry's record overwrote the rolled-back one

    def test_advancing_clock_keyed_and_second_commit(self):
        eng, persisted = self.check(True, history_key=KEY, second_commit=True)
        self.assertEqual([r.sequence for r in persisted], [1, 2])


class ReconcilePersistedLog(unittest.TestCase):
    def test_naive_log_reconciles_to_engine_records(self):
        for advance in (False, True):
            eng, persisted = write_raise_retry(NaiveAppendHook(), advance_clock=advance, second_commit=True)
            got = C.reconcile_persisted_log(persisted)
            self.assertEqual(list(got), list(eng.records))
            self.assertTrue(C.verify_record_chain(got))
            self.assertEqual(list(C.reconcile_persisted_log(persisted, engine_records=eng.records)), list(eng.records))
            if advance:
                print("\n  reconcile_persisted_log(naive log seqs %s) -> seqs %s, equals engine.records %s, chain %s"
                      % ([r.sequence for r in persisted], [r.sequence for r in got], list(got) == list(eng.records),
                         C.verify_record_chain(got)), end="")

    def test_json_round_trip_entries(self):
        eng, persisted = write_raise_retry(NaiveAppendHook(), advance_clock=True, second_commit=True)
        as_json = [json.loads(json.dumps(asdict(r))) for r in persisted]
        self.assertEqual(list(C.reconcile_persisted_log(as_json)), list(eng.records))

    def test_rolled_back_record_never_retried(self):
        # Hook writes seq 2 and raises; nobody retries. The log alone cannot tell (documented limitation);
        # reconciling against engine.records drops the phantom record.
        hook = NaiveAppendHook(fail_on=(2,))
        signer, clock, eng = make_engine(hook)
        eng.commit(*signed(eng, signer, F.mutation()))
        with self.assertRaises(OSError):
            eng.commit(*signed(eng, signer, F.mutation(0.40), pid="p-2", nonce="n-2", det="d-2"))
        self.assertEqual([r.sequence for r in eng.records], [1])
        self.assertEqual([r.sequence for r in C.reconcile_persisted_log(hook.log)], [1, 2])
        self.assertEqual(list(C.reconcile_persisted_log(hook.log, engine_records=eng.records)), list(eng.records))

    def test_tamper_gap_and_keys(self):
        eng, persisted = write_raise_retry(UpsertHook(), advance_clock=False, history_key=KEY, second_commit=True)
        self.assertEqual(len(C.reconcile_persisted_log(persisted, history_key=KEY)), 2)
        self.assertEqual(C.reconcile_persisted_log(persisted), ())                   # keyed log, no key
        self.assertEqual(C.reconcile_persisted_log(persisted, history_key=b"w" * 32), ())
        bad = [persisted[0], replace(persisted[1], reason="TAMPERED")]
        self.assertEqual(list(C.reconcile_persisted_log(bad, history_key=KEY)), persisted[:1])
        self.assertEqual(list(C.reconcile_persisted_log([persisted[1]], history_key=KEY)), [])   # gap at seq 1
        self.assertEqual(C.reconcile_persisted_log([]), ())

    def test_malformed_entries_and_bad_engine_records(self):
        eng, persisted = write_raise_retry(UpsertHook(), advance_clock=False)
        for junk in ([object()], [{"sequence": 1}], [replace(persisted[0], sequence="1")], [replace(persisted[0], sequence=0)]):
            with self.assertRaises(C.Refusal):
                C.reconcile_persisted_log(junk)
        with self.assertRaises(C.Refusal):
            C.reconcile_persisted_log(persisted, engine_records=[replace(persisted[0], reason="x")])

    def test_docstrings_document_the_contract(self):
        doc = C.CommitEngine.__init__.__doc__
        for phrase in ("may be called for a commit that is later rolled back", "idempotent upserts keyed by",
                       "must not re-enter", "reconcile the persisted log", "no migration path"):
            self.assertIn(phrase, " ".join(doc.split()))
        self.assertIn("last write wins", C.reconcile_persisted_log.__doc__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
