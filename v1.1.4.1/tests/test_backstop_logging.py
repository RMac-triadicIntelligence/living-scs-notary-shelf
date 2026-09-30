"""v1.1.4.1: the commit pre-commit backstop logs a WARNING with exc_info when it converts an unexpected
exception into Refusal('malformed input: ...'). Run: python3 -m unittest -v tests/test_backstop_logging.py"""
import io, logging, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "v114"))
from living_scs_v114 import core as C
from living_scs_v114 import fixtures as F


def signed_bad_set_path(eng, signer):
    # Genuinely signed {"op":"set","path":5}: every gate passes, then apply_mutation hits list(5) -> TypeError.
    bad = C.MutationProposal("bp", "organism-alpha", eng.state_digest, "personality_drift",
                             {"op": "set", "path": 5, "value": 1}, F.evidence(), F.interpretation(),
                             C.POLICY_VERSION, "juvenile", F.NOW, "e" * 64)
    bt = C.make_trace(bad, trace_id="t-bp", created_at=F.NOW)
    ba = signer.issue(bt, bad, decision=C.Decision.AUTHORIZE, determination_id="db", nonce="nb",
                      issued_at=F.NOW, expires_at=F.NOW + 600)
    return bad, bt, ba


class BackstopLogging(unittest.TestCase):
    def test_backstop_logs_warning_with_exc_info(self):
        signer, clock, eng = F.engine()
        with self.assertLogs(C.__name__, level="WARNING") as cm:
            with self.assertRaises(C.Refusal) as rc:
                eng.commit(*signed_bad_set_path(eng, signer))
        self.assertEqual(str(rc.exception), "malformed input: TypeError")
        self.assertIsInstance(rc.exception.__cause__, TypeError)            # chained cause still present
        self.assertEqual(len(cm.records), 1)
        rec = cm.records[0]
        self.assertEqual(rec.levelno, logging.WARNING)
        self.assertEqual(rec.name, C.__name__)
        self.assertIn("backstop", rec.getMessage()); self.assertIn("TypeError", rec.getMessage())
        self.assertIsNotNone(rec.exc_info); self.assertIs(rec.exc_info[0], TypeError)
        self.assertIs(rec.exc_info[1], rc.exception.__cause__)
        print("\n  logged: %s %s: %s | exc_info=%s" % (rec.levelname, rec.name, rec.getMessage(), rec.exc_info[0].__name__), end="")
        self.assertEqual(eng.records, ()); self.assertFalse(eng._commit_in_progress)

    def test_ordinary_refusals_do_not_log(self):
        signer, clock, eng = F.engine()
        p, t, a = signed_bad_set_path(eng, signer)
        logger = logging.getLogger(C.__name__)
        stream = io.StringIO(); handler = logging.StreamHandler(stream); logger.addHandler(handler)
        try:
            with self.assertRaises(C.Refusal):
                eng.commit(p, t, None)                                      # plain Refusal, no backstop
            with self.assertRaises(C.Refusal):
                eng.commit(p, t, a, reason="x\udfff")                        # validation-layer Refusal
        finally:
            logger.removeHandler(handler)
        self.assertEqual(stream.getvalue(), "")

    def test_library_is_silent_without_logging_config(self):
        # NullHandler on the library logger: nothing reaches logging.lastResort (stderr) by default.
        self.assertTrue(any(isinstance(h, logging.NullHandler) for h in logging.getLogger(C.__name__).handlers))


if __name__ == "__main__":
    unittest.main(verbosity=2)
