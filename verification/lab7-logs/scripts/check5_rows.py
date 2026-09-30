"""Claim 5 detail: per-row outcomes of run_corpus_oop, tagging WHERE each refusal happened:
  client-resolve  = harness resolve() raised in the runner; nothing sent to notary
  client-encode   = organism-side wire.encode refused (e.g. inf); nothing sent to notary
  notary          = reply came from the notary process
Source of run_corpus_oop.py is patched in memory only (file untouched)."""
import os, sys, runpy, json
V115 = sys.argv[1]; corpus = sys.argv[2]
os.chdir(V115); sys.path.insert(0, V115)
src = open("run_corpus_oop.py").read()
src = src.replace('rows.append((att.get("id"), "ADAPTER_REFUSE", str(e)[:60]))',
                  'rows.append((att.get("id"), "ADAPTER_REFUSE", "[client-resolve] " + str(e)[:60]))')
src = src.replace('''            try:
                reply = org.request({"op": "commit", "submission": sub})''','''            try:
                try:
                    payload = wire.encode({"op": "commit", "submission": sub})
                except wire.WireRefusal as e:
                    raise wire.WireRefusal("[client-encode] " + str(e))
                reply = org.raw(payload); reply["reason"] = "[notary] " + reply.get("reason", "")''')
src = src.replace('    h.shutdown()\n', '    h.shutdown()\n    [print("ROW %-28s %-15s %s" % r) for r in rows]\n', 1)
sys.argv = ["run_corpus_oop.py", corpus]
g = {"__name__": "__main__", "__file__": os.path.join(V115, "run_corpus_oop.py")}
try:
    exec(compile(src, "run_corpus_oop.py(patched-in-memory)", "exec"), g)
except SystemExit:
    pass
