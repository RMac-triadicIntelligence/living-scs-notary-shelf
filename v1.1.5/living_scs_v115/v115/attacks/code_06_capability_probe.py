# Attacker probes OS-level reach into the notary process. It only REPORTS booleans
# (can it open /proc/<pid>/mem, /environ, /maps, send signals) - it does NOT attempt
# a working memory-injection exploit. This measures whether the process boundary is
# backed by OS isolation or merely by convention.
import os
r=result
pid=material.get("_notary_pid")
r["target_pid"]=pid
def can(path):
    try:
        with open(path,"rb") as f: f.read(1); return True
    except Exception as e: return type(e).__name__
if pid:
    r["proc_status_readable"]=can("/proc/%d/status"%pid)
    r["proc_environ_readable"]=can("/proc/%d/environ"%pid)
    r["proc_mem_readable"]=can("/proc/%d/mem"%pid)
    r["proc_maps_readable"]=can("/proc/%d/maps"%pid)
    try:
        os.kill(pid,0); r["signal_reachable"]=True
    except Exception as e:
        r["signal_reachable"]=type(e).__name__
    # read notary uid from its /proc/<pid>/status if visible (judge-independent fact)
    try:
        for line in open("/proc/%d/status"%pid):
            if line.startswith("Uid:"): r["notary_status_uid"]=line.split()[1]; break
    except Exception as e:
        r["notary_status_uid"]=type(e).__name__
r["my_uid"]=os.getuid()
