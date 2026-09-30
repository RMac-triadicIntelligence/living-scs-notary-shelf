"""L4-1 regression: persist_hook re-entrancy must not double-commit.

Drop into /workspace/lab4/ next to common.py. Runs with pytest or plain python.
Uses only APIs exercised by the lab4 proof scripts.

Pre-fix expected: test_reentrant_commit_refused FAILS (2 records, seq [1,1],
verify_history False). Post-fix: all PASS.
"""
import common

m = common.real_module()


def _session(hook):
    eng, mat, *_ = common.new_session(m, persist_hook=hook)
    return eng, mat["ISSUED"]


def _legit_digest():
    eng, iss = _session(None)
    eng.commit(iss["proposal"], iss["trace"], iss["auth"])
    return eng.state_digest


def test_reentrant_commit_refused():
    """Hook re-enters commit with same material; swallows the error."""
    box, seen = {}, {"calls": 0, "exc": None}

    def hook(record, new_state):
        seen["calls"] += 1
        if seen["calls"] == 1:
            try:
                box["eng"].commit(box["p"], box["t"], box["a"], reason="reentrant")
            except Exception as e:
                seen["exc"] = e

    eng, iss = _session(hook)
    box.update(eng=eng, p=iss["proposal"], t=iss["trace"], a=iss["auth"])
    eng.commit(iss["proposal"], iss["trace"], iss["auth"], reason="outer")

    assert isinstance(seen["exc"], m.Refusal), f"re-entry not refused: {seen['exc']!r}"
    assert seen["calls"] == 1, f"hook ran {seen['calls']}x"
    assert [r.sequence for r in eng.records] == [1]
    assert eng.verify_history() is True
    assert eng.state_digest == _legit_digest()


def test_reentrant_refusal_propagates_atomically():
    """Hook lets the re-entry Refusal escape: outer commit must leave no trace."""
    box, armed = {}, {"on": True}

    def hook(record, new_state):
        if armed["on"]:  # one-shot: pre-fix engines would otherwise recurse to RecursionError
            armed["on"] = False
            box["eng"].commit(box["p"], box["t"], box["a"])

    eng, iss = _session(hook)
    box.update(eng=eng, p=iss["proposal"], t=iss["trace"], a=iss["auth"])
    before = common.deep_snapshot(m, eng)
    try:
        eng.commit(iss["proposal"], iss["trace"], iss["auth"])
    except m.Refusal:
        pass
    else:
        raise AssertionError("outer commit should fail when hook raises")
    assert common.diff_snapshot(before, common.deep_snapshot(m, eng)) == {}


def test_guard_resets_after_reentry():
    """Guard flag must reset (try/finally). After a refused re-entry, the next
    commit must be judged on its merits, not refused as re-entrant."""
    box, state = {}, {"armed": True}

    def hook(record, new_state):
        if state["armed"]:
            state["armed"] = False
            try:
                box["eng"].commit(box["p"], box["t"], box["a"])
            except m.Refusal:
                pass

    eng, mat, *_ = common.new_session(m, persist_hook=hook)
    iss = mat["ISSUED"]
    box.update(eng=eng, p=iss["proposal"], t=iss["trace"], a=iss["auth"])
    eng.commit(iss["proposal"], iss["trace"], iss["auth"])
    ref = mat["REFUSED"]
    try:
        eng.commit(ref["proposal"], ref["trace"], ref["auth"])
    except m.Refusal as e:
        assert "re-entrant" not in str(e).lower(), f"guard stuck: {e}"
    else:
        raise AssertionError("REFUSE-decision material was accepted")


def test_l4_17_still_holds():
    """Existing property: a raising hook commits nothing."""
    def boom(record, new_state):
        raise RuntimeError("disk full")

    eng, iss = _session(boom)
    before = common.deep_snapshot(m, eng)
    try:
        eng.commit(iss["proposal"], iss["trace"], iss["auth"])
    except RuntimeError:
        pass
    assert common.diff_snapshot(before, common.deep_snapshot(m, eng)) == {}


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print("PASS", name)
            except Exception as e:
                fails += 1; print("FAIL", name, "-", type(e).__name__, str(e)[:120])
    raise SystemExit(1 if fails else 0)
