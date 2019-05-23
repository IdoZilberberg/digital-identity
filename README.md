# digital-identity

## Keys

* `issuer.json` needs to contain a legit ed25519 key pair


## Running
You'll need 2 docker containers: one to compute hashes, another to generate proof

* Make sure you're in the main project this (where this file is)
* Open terminal:
* `docker run --name zok_gen_proof -v $PWD/code_gen_proof:/home/zokrates/code -ti zokrates/zokrates /bin/bash`


* Open another terminal:
* `docker container rename <current_name> zok_compute_hash`
-- and again --
* `docker run --name zok_compute_hash -v $PWD/code_compute_hash:/home/zokrates/code -ti zokrates/zokrates /bin/bash`
* `cp code/out* .`

* `docker container rename <current_name> zok_generate_proof`

Login to a running container:
* RUN ONCE IN ADVANCE: ./zokrates compile -i code/compute_hash.code
* `cp out.code out code` 
* `chmod 755 out`
* ./zokrates compute-witness -a 0 0 0 0




docker exec -d zok_compute_hash /bin/bash -c "./zokrates compute-witness -a secret name birth_year 0 > code/witness_1.log"
cat code_compute_hash/witness_1.log| tail -2 | sort | awk '{print $2}'
Extract 0 from line 0 and 1 from line 1

docker exec -d zok_compute_hash /bin/bash -c "./zokrates compute-witness -a secret name birth_year nonce > code/witness_2.log"
cat code_compute_hash/witness_2.log| tail -2 | sort | awk '{print $2}'

* zok_gen_proof
