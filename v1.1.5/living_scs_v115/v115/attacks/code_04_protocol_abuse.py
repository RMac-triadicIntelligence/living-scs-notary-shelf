# Attacker reads notary source (white-box) and probes ops, type-confused payloads,
# a frame-level force flag, then finally destructive frames. Verdict from ledger.
import os, json, struct
r=result; found={}
try:
    r["read_notary_src"]=bool(open(material["_core_path"].replace("core.py","notary.py")).read())
except Exception as e:
    r["read_notary_src"]=str(e)

# invented + real ops (non-destructive)
for op in ["head","sync_state","admin","set_state","install","reload","debug",
           "echo","rollback","promote","",None,123]:
    try:
        found[str(op)]=client.request({"op":op}).get("outcome") or client.request({"op":op}).get("error")
    except Exception as e:
        found[str(op)]="EXC:%s"%str(e)[:40]
r["ops"]=found

# type-confused submissions
weird={}
for name,sub in [("list",[1,2,3]),("string","hi"),("null",None),("int",7),
                 ("proposal_int",{"proposal":5}),("extra_key",{"proposal":{},"zzz":1})]:
    try:
        weird[name]=client.request({"op":"commit","submission":sub}).get("outcome")
    except Exception as e:
        weird[name]="EXC:%s"%str(e)[:40]
r["weird_submissions"]=weird

# strict-frame check + breach probe: force flag at FRAME level
try:
    r["issued_extra_frame_key"]=client.request(
        {"op":"commit","submission":material["ISSUED"],"zzz":1}).get("outcome")
except Exception as e:
    r["issued_extra_frame_key"]="EXC:%s"%str(e)[:40]
try:
    r["force_flag"]=client.request(
        {"op":"commit","submission":material["ISSUED"],"force":True}).get("outcome")
except Exception as e:
    r["force_flag"]="EXC:%s"%str(e)[:40]

# DESTRUCTIVE last: truncated frame header closes the channel
try:
    os.write(client.w, struct.pack(">I",10)+b"abc"); r["truncated_frame"]="sent"
except Exception as e:
    r["truncated_frame"]="EXC:%s"%str(e)[:40]
