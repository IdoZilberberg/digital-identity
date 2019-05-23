#!/bin/bash


chmod 755 ./proof-to-tx.py
./proof-to-tx.py ../code_gen_proof/proof.json ./transaction.json

gamma-cli send-tx transaction.json -env experimental
