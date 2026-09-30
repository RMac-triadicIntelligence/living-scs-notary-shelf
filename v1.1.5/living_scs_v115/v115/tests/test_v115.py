"""test_v115.py - unit + integration tests for the Living SCS v1.1.5 notary layer.

Scope is the NEW v1.1.5 surface only (the wire, the supervisor's pin gate, the
out-of-process notary). The engine itself (core.py, hash 23299fdc...) is unchanged
from v1.1.4.1 and keeps its own 36-unit suite; the one engine test here (N6) just
re-pins the message the walker emits on a non-finite number, because the wire now
sits in front of that path and we want a regression anchor if the wire ever changes.

    python3 -m unittest -v tests.test_v115         # from the v115/ directory
"""
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))   # .../v115/tests
V115 = os.path.dirname(HERE)                         # .../v115
ROOT = os.path.dirname(V115)                         # .../pkg115
sys.path.insert(0, V115)

import wire            # noqa: E402
import supervisor      # noqa: E402
import session         # noqa: E402


def load_core():
    p = os.path.join(ROOT, "v114", "living_scs_v114", "core.py")
    spec = importlib.util.spec_from_file_location("living_scs_v114.core", p)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m          # register BEFORE exec: dataclass forward-refs need it
    spec.loader.exec_module(m)
    return m


def nest_lists(depth):
    """A JSON value nested exactly `depth` containers deep, as raw bytes."""
    return b"[" * depth + b"]" * depth


# --------------------------------------------------------------------------- wire: depth scanner

class TestWireDepthScanner(unittest.TestCase):
    def test_depth_at_cap_ok(self):
        # MAX_WIRE_DEPTH containers deep is accepted (depth reaches the cap, not past it).
        wire.check_depth(nest_lists(wire.MAX_WIRE_DEPTH))          # must not raise

    def test_depth_one_past_cap_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.check_depth(nest_lists(wire.MAX_WIRE_DEPTH + 1))

    def test_brackets_inside_strings_do_not_count(self):
        # 500 openers, all inside one string value -> real depth is 1.
        raw = b'{"k":"' + b"[" * 500 + b'"}'
        wire.check_depth(raw)                                       # must not raise
        self.assertEqual(wire.decode(raw), {"k": "[" * 500})

    def test_escaped_quote_keeps_string_open(self):
        # the \" must NOT close the string, so the following brackets stay quoted.
        raw = b'{"k":"a\\"' + b"[" * 500 + b'b"}'
        wire.check_depth(raw)                                       # must not raise
        self.assertEqual(wire.decode(raw), {"k": 'a"' + "[" * 500 + "b"})

    def test_mixed_container_kinds_balance(self):
        raw = b'{"a":[{"b":[1,2,3]}]}'
        wire.check_depth(raw)
        self.assertEqual(wire.decode(raw), {"a": [{"b": [1, 2, 3]}]})


# --------------------------------------------------------------------------- wire: encode/decode

class TestWireEncodeDecode(unittest.TestCase):
    def test_roundtrip_submission_shape(self):
        obj = {"op": "commit", "submission": {"proposal": {"mutation": {"op": "x", "value": [1, 2, 3]}},
                                              "reason": "r"}}
        self.assertEqual(wire.decode(wire.encode(obj)), obj)

    def test_roundtrip_at_the_cap(self):
        # a real roundtrip through the door path at exactly the depth cap.
        x = 0
        for _ in range(wire.MAX_WIRE_DEPTH):
            x = [x]                                                 # exactly MAX_WIRE_DEPTH containers
        self.assertEqual(wire.decode(wire.encode(x)), x)

    def test_encoder_is_iterative_under_low_recursionlimit(self):
        # Build a value far deeper than any recursion limit, then encode it with the
        # interpreter's recursion limit set very low. A recursive encoder would raise
        # RecursionError here; the iterative one must not. (This is the wire docstring's
        # promise: the judge can build arbitrarily deep test frames regardless of the limit.)
        depth = 3000
        x = 0
        for _ in range(depth):
            x = [x]                                                 # exactly `depth` containers around an int
        saved = sys.getrecursionlimit()
        sys.setrecursionlimit(300)
        try:
            raw = wire.encode(x)
        finally:
            sys.setrecursionlimit(saved)
        # leading/trailing bracket run proves the full depth was emitted
        self.assertEqual(raw[:depth], b"[" * depth)
        self.assertEqual(raw[-depth:], b"]" * depth)

    def test_normal_float_roundtrips(self):
        self.assertEqual(wire.encode(1.5), b"1.5")
        self.assertEqual(wire.decode(b"[1.5]"), [1.5])


# --------------------------------------------------------------------------- wire: non-finite, both directions

class TestWireNonFinite(unittest.TestCase):
    def test_encode_nan_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.encode(float("nan"))

    def test_encode_pos_inf_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.encode(float("inf"))

    def test_encode_neg_inf_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.encode(float("-inf"))

    def test_encode_nested_non_finite_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.encode({"x": [1.0, 2.0, float("inf")]})

    def test_decode_infinity_token_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.decode(b'{"x": Infinity}')

    def test_decode_nan_token_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.decode(b'{"x": NaN}')


# --------------------------------------------------------------------------- wire: framing / strictness

class TestWireFraming(unittest.TestCase):
    def test_framebuffer_reassembles_split_frame(self):
        payload = wire.encode({"op": "head"})
        f = wire.frame(payload)
        fb = wire.FrameBuffer()
        self.assertEqual(fb.feed(f[:3]), [])          # header incomplete
        self.assertEqual(fb.feed(f[3:]), [payload])   # completes to exactly one frame

    def test_framebuffer_splits_two_frames(self):
        a, b = wire.encode({"op": "head"}), wire.encode({"op": "shutdown"})
        fb = wire.FrameBuffer()
        self.assertEqual(fb.feed(wire.frame(a) + wire.frame(b)), [a, b])

    def test_oversize_payload_refused_on_send(self):
        with self.assertRaises(wire.WireError):
            wire.frame(b"x" * (wire.MAX_FRAME + 1))

    def test_declared_oversize_length_refused(self):
        fb = wire.FrameBuffer()
        with self.assertRaises(wire.WireError):
            fb.feed(struct.pack(">I", wire.MAX_FRAME + 1))

    def test_duplicate_key_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.decode(b'{"a":1,"a":2}')

    def test_non_utf8_refused(self):
        with self.assertRaises(wire.WireRefusal):
            wire.decode(b'{"a":"\xff\xfe"}')


# --------------------------------------------------------------------------- supervisor: pin gate

class TestSupervisorPins(unittest.TestCase):
    def setUp(self):
        self.pins = supervisor.pins_for(ROOT)
        self.originals = {n: os.path.join(ROOT, rel) for n, rel in supervisor.SOURCES.items()}

    def test_self_pins_verify(self):
        supervisor.verify(self.originals, self.pins)              # must not raise

    def test_single_byte_change_detected(self):
        d = tempfile.mkdtemp(prefix="lscs_pintest_")
        try:
            copies = {}
            for n, src in self.originals.items():
                dst = os.path.join(d, n)
                with open(src, "rb") as f:
                    data = bytearray(f.read())
                if n == "wire.py":
                    data[len(data) // 2] ^= 0x01                  # flip one bit in the middle
                with open(dst, "wb") as f:
                    f.write(data)
                copies[n] = dst
            with self.assertRaises(supervisor.PinMismatch) as cm:
                supervisor.verify(copies, self.pins)
            self.assertIn("wire.py", str(cm.exception))
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def test_missing_pin_refused(self):
        with self.assertRaises(supervisor.PinMismatch):
            supervisor.verify(self.originals, {})                 # empty PINS => refuse to launch


# --------------------------------------------------------------------------- engine: N6 non-finite reason

class TestEngineNonFiniteReason(unittest.TestCase):
    """The wire now rejects non-finite numbers first, so a non-finite can no longer
    reach the engine over the pipe. These tests pin the engine's own last-line-of-
    defense message directly, as a regression anchor independent of the wire."""
    @classmethod
    def setUpClass(cls):
        cls.m = load_core()

    def test_refusal_is_permissionerror(self):
        self.assertTrue(issubclass(self.m.Refusal, PermissionError))

    def test_walker_reports_non_finite_in_object(self):
        with self.assertRaises(self.m.Refusal) as cm:
            self.m._req_object({"x": float("nan")}, "sub")
        self.assertIn("non-finite", str(cm.exception))

    def test_scalar_number_must_be_finite(self):
        with self.assertRaises(self.m.Refusal) as cm:
            self.m._req_number(float("inf"), "n")
        self.assertIn("finite", str(cm.exception))


# --------------------------------------------------------------------------- notary: end-to-end over the pipe

class TestNotaryPipeSmoke(unittest.TestCase):
    """One notary, local isolation (no attacker code), driven entirely over the wire.
    The verdict on every step is read back from the notary's ledger via the judge
    channel - never from an in-process object."""
    @classmethod
    def setUpClass(cls):
        cls.cfg, cls.material = session.build(ROOT)
        cls.h = supervisor.NotaryHandle(ROOT, cls.cfg, isolation="local",
                                        pins=supervisor.pins_for(ROOT))
        cls.org = supervisor.OrgClient(cls.h.org_w, cls.h.org_r)

    @classmethod
    def tearDownClass(cls):
        cls.h.shutdown()

    def _sub(self, name):
        e = self.material[name]
        return {"proposal": e["proposal"], "trace": e["trace"], "auth": e["auth"]}

    def test_full_sequence_ledger_is_the_record(self):
        h, org = self.h, self.org

        # 0. empty ledger, juvenile, history verifies
        head = h.head()
        self.assertEqual(len(head["records"]), 0)
        self.assertEqual(head["state"]["maturity"], "juvenile")
        self.assertTrue(head["verify_history"])

        # 1. the legitimately-signed authorize is ACCEPTed and lands as record 1
        r = org.request({"op": "commit", "submission": self._sub("ISSUED")})
        self.assertEqual(r["outcome"], "ACCEPT")
        self.assertEqual(len(h.head()["records"]), 1)

        # 2. the signed-but-REFUSED target (set_maturity=mature) does not move the ledger
        r = org.request({"op": "commit", "submission": self._sub("REFUSED")})
        self.assertIn(r["outcome"], ("REFUSE", "ADAPTER_REFUSE"))
        head = h.head()
        self.assertEqual(len(head["records"]), 1)
        self.assertEqual(head["state"]["maturity"], "juvenile")

        # 3. replaying the accepted authorize is refused (no second record)
        r = org.request({"op": "commit", "submission": self._sub("ISSUED")})
        self.assertEqual(r["outcome"], "REFUSE")
        self.assertEqual(len(h.head()["records"]), 1)

        # 4. an over-deep but well-framed frame is refused at the door, engine untouched
        deep = b'{"op":"commit","submission":' + b"[" * 130 + b"]" * 130 + b"}"
        r = org.raw(deep)
        self.assertEqual(r["outcome"], "WIRE_REFUSE")

        # 5. an unknown op / extra field is refused; channel still usable afterwards
        r = org.request({"op": "commit", "submission": self._sub("ISSUED"), "extra": 1})
        self.assertEqual(r["outcome"], "WIRE_REFUSE")

        # final: exactly one record, still juvenile, history still verifies, no empty organs
        head = h.head()
        self.assertEqual(len(head["records"]), 1)
        self.assertEqual(head["state"]["maturity"], "juvenile")
        self.assertFalse(head["state"]["organs"])
        self.assertTrue(head["verify_history"])


# --------------------------------------------------------------------------- host recursion-limit invariance

class TestHostRecursionInvariance(unittest.TestCase):
    """The equivalence lane must produce the same verdicts regardless of the host
    interpreter's recursion limit: the wire's iterative encode/depth-scan means the
    corpus means the same thing whether the limit is 300 or 5000. Runs the OOP corpus
    lane in a subprocess at three limits and requires GREEN with zero faults each."""
    CORPUS = os.path.join(ROOT, "v114", "grok_attacks.json")

    def _run_at(self, limit):
        run = os.path.join(V115, "run_corpus_oop.py")
        code = (
            "__file__=%r; import sys; sys.setrecursionlimit(%d); "
            "sys.argv=[__file__, %r]; "
            "exec(compile(open(__file__).read(), __file__, 'exec'))"
            % (run, limit, self.CORPUS)
        )
        return subprocess.run([sys.executable, "-c", code], cwd=V115,
                              capture_output=True, text=True, timeout=120)

    def test_invariant_across_limits(self):
        for limit in (300, 1000, 5000):
            with self.subTest(recursionlimit=limit):
                p = self._run_at(limit)
                self.assertEqual(p.returncode, 0, msg=p.stdout + p.stderr)
                self.assertIn("faults: 0", p.stdout)
                self.assertIn("GREEN", p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
