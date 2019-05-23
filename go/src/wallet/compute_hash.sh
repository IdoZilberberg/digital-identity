#!/bin/bash

SECRET=$1
NAME=$2
BIRTH_YEAR=$3
NONCE=$4


docker exec -d zok_compute_hash /bin/bash -c "./zokrates compute-witness -a $SECRET $NAME $BIRTH_YEAR $NONCE > code/witness_hashed_id.log"
sleep 1
echo $(cat ../code_compute_hash/witness_hashed_id.log | tail -2 | sort | head -1 | cut -d" " -f2),$(cat ../code_compute_hash/witness_hashed_id.log | tail -2 | sort | tail -1| cut -d" " -f2)
