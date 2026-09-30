# Attacker attempts PTRACE_ATTACH to the notary (then immediately detaches). This
# is the honest test of whether the process boundary is OS-enforced. It does NOT
# read or modify engine state - attach+detach only - but a successful attach means
# an OS-capable same-uid adversary could read the in-process history key. Verdict is
# still taken from the ledger (attach alone changes nothing there).
import ctypes, os, signal, time
r=result
pid=material.get("_notary_pid")
r["target_pid"]=pid; r["my_uid"]=os.getuid()
libc=ctypes.CDLL("libc.so.6",use_errno=True)
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
res=libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
err=ctypes.get_errno()
if res==0:
    r["ptrace_attach"]="SUCCESS - notary memory is reachable by this uid"
    try:
        os.waitpid(pid,0)
    except Exception: pass
    libc.ptrace(PTRACE_DETACH, pid, 0, 0)   # detach, leave it running
    r["detached"]=True
else:
    r["ptrace_attach"]="DENIED: %s"%os.strerror(err)
