#!/usr/bin/python

import os
import json

with open("proof.json", "r") as f:
    j=json.load(f)

arguments = [','.join(j["proof"]["a"]), ','.join([','.join(k) for k in j["proof"]["b"]]), ','.join(j["proof"]["c"]), ','.join(j["inputs"])]

output = {"ContractName": "Over18", "MethodName": "VerifyProof", "Arguments": [ {"type": "string", "value": v} for v in arguments] }

with open('transaction.json', 'w') as f:
    json.dump(output, f, indent=4)
