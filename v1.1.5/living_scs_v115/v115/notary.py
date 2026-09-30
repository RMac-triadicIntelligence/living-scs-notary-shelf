"""notary.py - out-of-process authorization notary (Living SCS v1.1.5).

The organism may PROPOSE; only the notary's ledger decides what happened.

The notary runs the unmodified v1.1.4.1 CommitEngine (core.py, hash-pinned by the
supervisor) in its own process. It holds no private key: only the pinned public
key, a history key the organism never sees, and the ledger. It accepts nothing
but framed JSON (wire.py) and reuses the harness adapter (lscs_harness.py), so its
input channel is exactly the channel the 103 corpus attempts and 20,339 fuzz
trials already exercised in-process.

Two channels, never mixed:
  organism channel: {"op":"commit","submission":{...}}  {"op":"head"}
  judge channel:    {"op":"head"}  {"op":"shutdown"}
The organism channel is non-blocking both ways: a slow, silent, or flooding
organism loses its own channel; it cannot stall the judge.

    python3 notary.py CONFIG ORG_R ORG_W JUDGE_R JUDGE_W
"""
import importlib.util
import json
import os
import selectors
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wire  # noqa: E402

SUB_KEYS = {"proposal", "trace", "auth", "artifact", "reason"}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Channel:
    def __init__(self, name, rfd, wfd):
        self.name, self.rfd, self.wfd = name, rfd, wfd
        self.buf = wire.FrameBuffer()
        self.open = True
        os.set_blocking(rfd, False)
        os.set_blocking(wfd, False)

    def send(self, obj):
        data = wire.frame(wire.encode(obj))
        try:
            n = os.write(self.wfd, data)
        except (BlockingIOError, BrokenPipeError, OSError):
            n = -1
        if n != len(data):          # peer not reading (or gone): it loses the channel
            self.close()

    def close(self):
        if self.open:
            self.open = False
            for fd in (self.rfd, self.wfd):
                try:
                    os.close(fd)
                except OSError:
                    pass


class Notary:
    def __init__(self, cfg):
        self.m = m = load(os.path.join(HERE, "core.py"), "lscs_core")
        self.H = load(os.path.join(HERE, "lscs_harness.py"), "lscs_adapter")
        pub = bytes.fromhex(cfg["public_key_hex"])
        self.eng = m.CommitEngine(
            cfg["organism_id"], cfg["initial_state"],
            m.MinatoAuthority.verifier_only(cfg["authority_id"], m.Ed25519PublicKey.from_public_bytes(pub)),
            m.TrustedClock(cfg["clock_t0"]),
            expected_authority_id=cfg["authority_id"], expected_public_key=pub,
            history_key=bytes.fromhex(cfg["history_key_hex"]))

    def status(self):
        return {"sequence": len(self.eng.records), "state_digest": self.eng.state_digest}

    def commit(self, sub):
        m, H = self.m, self.H
        try:
            if type(sub) is not dict or "proposal" not in sub or set(sub) - SUB_KEYS:
                raise H.AdapterRefusal("submission needs proposal[, trace, auth, artifact, reason]")
            p = H.build_proposal(m, sub["proposal"])
            t = H.build_trace(m, sub.get("trace"))
            a = H.build_auth(m, sub.get("auth"))
            art = H.build_artifact(m, sub.get("artifact"))
            reason = sub.get("reason", "authorized mutation")
            if type(reason) is not str:
                raise H.AdapterRefusal("reason must be a string")
        except (H.AdapterRefusal, H.ParseRefusal) as e:
            return {"outcome": "ADAPTER_REFUSE", "reason": str(e)[:200]}
        try:
            self.eng.commit(p, t, a, reason=reason, artifact=art)
            return {"outcome": "ACCEPT", "reason": ""}
        except (m.Refusal, m.TraceError) as e:
            return {"outcome": "REFUSE", "reason": ("%s: %s" % (type(e).__name__, e))[:200]}

    def full_head(self):
        e = self.eng
        return {"state": e.state, "state_digest": e.state_digest, "verify_history": e.verify_history(),
                "records": [{"sequence": r.sequence, "resulting_digest": r.resulting_digest} for r in e.records],
                "pid": os.getpid(), "uid": os.getuid()}

    def on_organism(self, msg):
        if type(msg) is not dict or type(msg.get("op")) is not str:
            raise wire.WireRefusal("frame must be an object with a string op")
        op = msg["op"]
        if op == "commit" and set(msg) == {"op", "submission"}:
            return self.commit(msg["submission"])
        if op == "head" and set(msg) == {"op"}:
            return {"outcome": "HEAD", "reason": ""}
        raise wire.WireRefusal("unknown op or fields")

    def on_judge(self, msg):
        op = msg.get("op") if type(msg) is dict else None
        if op == "head":
            return self.full_head()
        if op == "shutdown":
            raise SystemExit(0)
        return {"error": "unknown judge op"}


def main():
    cfg_path, org_r, org_w, judge_r, judge_w = sys.argv[1], *map(int, sys.argv[2:6])
    with open(cfg_path) as f:
        cfg = json.load(f)
    os.unlink(cfg_path)                               # history key now lives only in this process
    notary = Notary(cfg)
    org, judge = Channel("organism", org_r, org_w), Channel("judge", judge_r, judge_w)
    sel = selectors.DefaultSelector()
    sel.register(org.rfd, selectors.EVENT_READ, org)
    sel.register(judge.rfd, selectors.EVENT_READ, judge)
    judge.send({"ready": True, "pid": os.getpid()})
    while judge.open:
        for key, _ in sel.select():
            ch = key.data
            try:
                data = os.read(ch.rfd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                data = b""
            try:
                if not data:
                    raise EOFError
                frames = ch.buf.feed(data)
            except (EOFError, wire.WireError):
                sel.unregister(ch.rfd)
                ch.close()
                continue
            for raw in frames:
                if not ch.open:
                    break
                if ch is judge:
                    try:
                        ch.send(notary.on_judge(wire.decode(raw)))
                    except wire.WireRefusal as e:
                        ch.send({"error": str(e)[:200]})
                    continue
                try:
                    reply = notary.on_organism(wire.decode(raw))
                except wire.WireRefusal as e:
                    reply = {"outcome": "WIRE_REFUSE", "reason": str(e)[:200]}
                except Exception as e:                # engine or adapter crashed: reported, notary survives
                    reply = {"outcome": "FAULT", "reason": ("%s: %s" % (type(e).__name__, e))[:200]}
                reply.update(notary.status())
                ch.send(reply)
            if not ch.open:
                try:
                    sel.unregister(ch.rfd)
                except (KeyError, ValueError):
                    pass


if __name__ == "__main__":
    main()
