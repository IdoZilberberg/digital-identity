#!/usr/bin/python

import os
import json
import sys



with open(sys.argv[1], "r") as f:
    j=json.load(f)

arguments = [','.join(j["proof"]["a"]), ','.join([','.join(k) for k in j["proof"]["b"]]), ','.join(j["proof"]["c"]), ','.join(j["inputs"])]

output = {"ContractName": "proof2", "MethodName": "VerifyProof", "Arguments": [ {"type": "string", "value": v} for v in arguments] }

with open(sys.argv[2], 'w') as f:
    json.dump(output, f, indent=4)
