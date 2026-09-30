"""wire.py - the only language the notary speaks (Living SCS v1.1.5).

Frame = 4-byte big-endian length + UTF-8 JSON object.

Lesson carried from v1.1.4 (the "count the boxes at the door" fix): nesting depth
is counted on the raw bytes with a loop BEFORE any parser runs, so no frame can
make the notary recurse. Encoding is also iterative, so the judge can build deep
test frames without depending on the interpreter's recursion limit.
"""
import json
import struct

MAX_FRAME = 2_000_000
MAX_WIRE_DEPTH = 96          # engine refuses nesting > 64 inside a submission; envelope adds <= 4


class WireError(Exception):
    """Framing is broken; the channel cannot be resynchronised and must close."""


class WireRefusal(Exception):
    """The frame is intact but refused before it reaches the engine."""


def frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME:
        raise WireError("frame %d > %d" % (len(payload), MAX_FRAME))
    return struct.pack(">I", len(payload)) + payload


class FrameBuffer:
    """Non-blocking reassembly: feed bytes, take complete frames. Never blocks, never recurses."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf += data
        out = []
        while len(self.buf) >= 4:
            (n,) = struct.unpack(">I", self.buf[:4])
            if n > MAX_FRAME:
                raise WireError("declared frame %d > %d" % (n, MAX_FRAME))
            if len(self.buf) < 4 + n:
                break
            out.append(bytes(self.buf[4:4 + n]))
            del self.buf[:4 + n]
        return out


def check_depth(raw: bytes) -> None:
    depth = 0
    in_str = esc = False
    for b in raw:
        if in_str:
            if esc:
                esc = False
            elif b == 0x5C:
                esc = True
            elif b == 0x22:
                in_str = False
        elif b == 0x22:
            in_str = True
        elif b == 0x7B or b == 0x5B:
            depth += 1
            if depth > MAX_WIRE_DEPTH:
                raise WireRefusal("nesting deeper than %d on the wire" % MAX_WIRE_DEPTH)
        elif b == 0x7D or b == 0x5D:
            depth -= 1


def decode(raw: bytes):
    """Strict: depth-checked first, UTF-8 only, no duplicate keys, no NaN/Infinity."""
    check_depth(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise WireRefusal("not UTF-8: %s" % e.reason)

    def pairs(ps):
        d = {}
        for k, v in ps:
            if k in d:
                raise WireRefusal("duplicate key %r" % (k[:40],))
            d[k] = v
        return d

    def const(c):
        raise WireRefusal("non-finite number %s" % c)

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=const)
    except WireRefusal:
        raise
    except (ValueError, RecursionError) as e:
        raise WireRefusal("bad JSON: %s" % str(e)[:80])


def encode(obj) -> bytes:
    """Iterative JSON encoder (no recursion, any depth). ASCII-escaped, so lone surrogates survive."""
    out, stack = [], [(False, obj)]
    while stack:
        literal, x = stack.pop()
        if literal:
            out.append(x)
        elif isinstance(x, dict):
            seq = [(True, "{")]
            for i, (k, v) in enumerate(x.items()):
                if type(k) is not str:
                    raise TypeError("non-string key")
                seq += [(True, ("," if i else "") + json.dumps(k) + ":"), (False, v)]
            seq.append((True, "}"))
            stack.extend(reversed(seq))
        elif isinstance(x, (list, tuple)):
            seq = [(True, "[")]
            for i, v in enumerate(x):
                if i:
                    seq.append((True, ","))
                seq.append((False, v))
            seq.append((True, "]"))
            stack.extend(reversed(seq))
        elif isinstance(x, float) and (x != x or x in (float("inf"), float("-inf"))):
            # a non-finite number cannot be put on the wire: the organism itself
            # is unable to express NaN/Infinity to the notary.
            raise WireRefusal("non-finite number is not encodable on the wire")
        else:
            out.append(json.dumps(x, allow_nan=False))
    return "".join(out).encode("ascii")
