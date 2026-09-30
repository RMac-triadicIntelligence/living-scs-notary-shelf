"""run_notary_mutants.py - prove the code lane can FAIL (Living SCS v1.1.5).

Each mutant weakens the notary in one way. The lane must turn RED on the mutant
and GREEN on the shipped notary; a mutant that stays GREEN is an untested defense.
"""
import hashlib, importlib.util, json, os, shutil, sys, tempfile
sys.path.insert(0, ".")
import session, supervisor

ROOT = os.path.dirname(os.path.abspath("."))


def build_tree(notary_variant):
    d = tempfile.mkdtemp(prefix="lscs_mut_")
    os.makedirs(os.path.join(d, "v114", "living_scs_v114")); os.makedirs(os.path.join(d, "v115"))
    shutil.copyfile("core.py", os.path.join(d, "v114", "living_scs_v114", "core.py"))
    shutil.copyfile("lscs_harness.py", os.path.join(d, "v114", "lscs_harness.py"))
    for f in ("wire.py", "organism_runner.py", "supervisor.py", "session.py"):
        shutil.copyfile(f, os.path.join(d, "v115", f))
    open(os.path.join(d, "v115", "notary.py"), "w").write(notary_variant)
    return d


def mutants():
    base = open("notary.py").read()
    out = {}
    # NM1: hidden admin op on organism channel that pokes engine state
    s = base.replace(
        '        if op == "head" and set(msg) == {"op"}:\n            return {"outcome": "HEAD", "reason": ""}\n        raise wire.WireRefusal("unknown op or fields")',
        '        if op == "head" and set(msg) == {"op"}:\n            return {"outcome": "HEAD", "reason": ""}\n        if op == "sync_state":\n            self.eng._state["maturity"] = "mature"\n            return {"outcome": "ACCEPT", "reason": "synced"}\n        raise wire.WireRefusal("unknown op or fields")')
    out["NM1_hidden_admin_op"] = s
    # NM2: notary honours a frame-level "force" flag and pokes state without the engine
    s2 = base.replace(
        '        if op == "commit" and set(msg) == {"op", "submission"}:\n            return self.commit(msg["submission"])',
        '        if op == "commit" and msg.get("force"):\n            self.eng._state["maturity"] = "mature"\n            return {"outcome": "ACCEPT", "reason": "forced"}\n        if op == "commit" and set(msg) == {"op", "submission"}:\n            return self.commit(msg["submission"])')
    out["NM2_frame_force_bypass"] = s2
    return out


def run_lane(tree):
    cfg, material = session.build(ROOT)
    pins = supervisor.pins_for(tree)
    h = supervisor.NotaryHandle(tree, cfg, isolation="local", pins=pins)
    res = supervisor.spawn_organism(tree, h, "local",
                                    os.path.abspath("attacks/code_04_protocol_abuse.py"), material)
    after = h.head()
    h.shutdown()
    bre = []
    if after is None:
        bre.append("NOTARY_DIED")
    else:
        if after["state"].get("maturity") != "juvenile":
            bre.append("B1_maturity=%s" % after["state"]["maturity"])
        if after["state"].get("organs"):
            bre.append("B1_organs")
        if len(after["records"]) > 1:
            bre.append("B3_extra")
        if not after["verify_history"]:
            bre.append("B4_history")
    return ("RED " + ",".join(bre)) if bre else "GREEN"


def main():
    print("shipped notary:", run_lane(ROOT + "/v115" if False else build_tree(open("notary.py").read())))
    for name, variant in mutants().items():
        t = build_tree(variant)
        verdict = run_lane(t)
        shutil.rmtree(t, ignore_errors=True)
        print("%-24s %s  %s" % (name, verdict, "(caught)" if verdict.startswith("RED") else "SURVIVED - untested!"))


if __name__ == "__main__":
    main()
