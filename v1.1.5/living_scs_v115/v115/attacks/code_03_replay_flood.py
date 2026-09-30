# Attacker floods the notary with the SAME legit ISSUED 25 times. Exactly one
# must ACCEPT (sequence 1); the rest must REFUSE (nonce/determination consumed).
r=result
outs=[]
for i in range(25):
    outs.append(client.request({"op":"commit","submission":material["ISSUED"]}).get("outcome"))
r["accepts"]=outs.count("ACCEPT")
r["refuses"]=outs.count("REFUSE")
r["sequence_of_outcomes"]=outs[:5]+["..."]+outs[-2:]
