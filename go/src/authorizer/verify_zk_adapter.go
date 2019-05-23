package main

import (
	"fmt"
	"github.com/digital-identity/go/src/util"
)

func verifyZKProofWithGammaCli() {

	out, err := util.RunExternal("./verify_proof.sh")
	if err != nil {
		util.Log("Error; %s", err)
	}
	fmt.Printf("Output: %s\n", out)
}

func verify(publicKey []byte, secretKey []byte, verificationKey []byte, proof *util.ZKProof) {

	//verificationKeyStr := util.B2HexS(verificationKey)
	//const virtualChainId = 42
	//client := orbs.NewClient("http://localhost:3000", virtualChainId, codec.NETWORK_TYPE_TEST_NET)
	//tx, txId, err := client.CreateTransaction(
	//	publicKey,
	//	secretKey,
	//	"ZKProof",
	//	"VerifyZKProof",
	//	verificationKeyStr, proof.String())
	//
	//util.Log(tx, txId, err)

	/*

		query, err = client.CreateQuery(
		    receiver.PublicKey,
		    "BenchmarkToken",
		    "getBalance",
		    receiver.AddressAsBytes())
		response, err := client.SendQuery(query)

	*/

	// SendTransaction...
	// See https://github.com/orbs-network/contract-library-experiment/tree/master/contract

}
