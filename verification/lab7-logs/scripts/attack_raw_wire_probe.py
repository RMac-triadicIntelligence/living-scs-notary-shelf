# lab7 probe (runs INSIDE organism_runner, like the shipped attacks). Sends RAW frames
# the organism-side encoder would never produce, to test what the NOTARY itself refuses.
import json
r = result
def raw(label, payload):
    try:
        rep = client.raw(payload)
        r[label] = "%s | %s" % (rep.get("outcome"), rep.get("reason", "")[:90])
    except Exception as e:
        r[label] = "EXC %s: %s" % (type(e).__name__, str(e)[:80])
iss = json.dumps(material["REFUSED"])            # a real signed submission text
def sub_with(path_fn):
    s = json.loads(iss); path_fn(s); return s
# 1) overflow literal 1e999 -> json.loads gives float('inf'); parse_constant does NOT catch it
p = json.dumps({"op": "commit", "submission": json.loads(iss)})
p_inf = p.replace('"score": 0.91', '"score": 1e999', 1)
raw("A_1e999_in_evidence_score", p_inf.encode())
p_ninf = p.replace('"score": 0.91', '"score": -1e999', 1)
raw("B_neg1e999_in_evidence_score", p_ninf.encode())
raw("C_Infinity_token", p.replace('"score": 0.91', '"score": Infinity', 1).encode())
raw("D_NaN_token", p.replace('"score": 0.91', '"score": NaN', 1).encode())
raw("E_dup_key_frame", b'{"op":"head","op":"head"}')
raw("F_lone_surrogate_reason", json.dumps({"op": "commit", "submission": dict(json.loads(iss), reason="\ud800x")}).encode())
raw("G_bigint_10e300_score", p.replace('"score": 0.91', '"score": ' + "1" + "0"*300, 1).encode())
raw("H_bigint_5000_digits", p.replace('"score": 0.91', '"score": ' + "9"*5000, 1).encode())
raw("I_depth_96", b'{"op":"head","x":' + b'[' * 95 + b']' * 95 + b'}')
raw("J_depth_97", b'{"op":"head","x":' + b'[' * 96 + b']' * 96 + b'}')
raw("K_non_utf8", b'{"op":"\xff"}')
raw("L_top_level_array", b'[1,2]')
raw("M_1e999_in_interp_confidence", p.replace('"confidence"', '"confidence"', 1).encode() if False else
    json.dumps({"op":"commit","submission":json.loads(iss)}).replace('"reason": ', '"reason": ', 1).encode())
r["ledger_note"] = "verdict comes from judge channel afterwards"
