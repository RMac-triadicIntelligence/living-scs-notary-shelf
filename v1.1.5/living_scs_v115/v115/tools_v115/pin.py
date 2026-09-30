"""pin.py - compute the sha256 pins for the files the notary executes and write them
into supervisor.PINS. Run once at release. supervisor.py is not itself in SOURCES,
so rewriting its PINS line does not invalidate any pin.

    python3 v115/tools_v115/pin.py            # ROOT is inferred (two levels up)
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))     # .../v115/tools_v115
V115 = os.path.dirname(HERE)                           # .../v115
ROOT = os.path.dirname(V115)                           # package root
sys.path.insert(0, V115)
import supervisor  # noqa: E402


def main():
    pins = supervisor.pins_for(ROOT)
    body = ",\n".join('        %r: %r' % (k, pins[k]) for k in sorted(pins))
    block = "PINS = {\n%s,\n}" % body
    sup = os.path.join(V115, "supervisor.py")
    src = open(sup).read()
    new = re.sub(r"PINS = \{[^}]*\}[^\n]*", block, src, count=1)
    if new == src:
        raise SystemExit("could not locate PINS placeholder in supervisor.py")
    open(sup, "w").write(new)
    for k in sorted(pins):
        print("%-16s %s" % (k, pins[k]))
    print("written to", sup)


if __name__ == "__main__":
    main()
