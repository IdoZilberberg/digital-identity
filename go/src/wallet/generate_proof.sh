#!/bin/bash

SECRET=$1
NAME=$2
BIRTH_YEAR=$3
hashedID0=$4
hashedID1=$5
NONCE=$6
RESPONSE0=$7
RESPONSE1=$8
#TIMESTAMP=$9

outfile=code/proof.json
# Example run:
# ./zokrates compute-witness -a 12345678901234567890 3565 1980 2019 152645680393079710119126394414383841086 130459242405821757297579536115588411684 010203040506 300833010901833986344554403152113040468 195279387529725283810926075206332074557
docker exec -d zok_gen_proof /bin/bash -c "./zokrates compute-witness -a $SECRET $NAME $BIRTH_YEAR 2019 $hashedID0 $hashedID1 $NONCE $RESPONSE0 $RESPONSE1"
sleep 5
docker exec -d zok_gen_proof /bin/bash -c "./zokrates generate-proof; cp proof.json ${outfile}"
sleep 3
echo "${outfile}"