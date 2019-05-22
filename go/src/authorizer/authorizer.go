package main

import (
	"github.com/digital-identity/go/src/util"
	"github.com/pkg/errors"
)

const ISSUER_PATH = "../issuer.json"
const PROOF_PATH = "../proof.json"
const VERIFICATION_KEY_PATH = "verification.key.txt"

func main() {
	util.Log("AUTHORIZER START")

	nonce := createNonce()
	issuer, err := util.ReadIssuerFromFile(ISSUER_PATH)
	util.ExitIfError("Error reading issuer", err)

	util.Log("Successfully read issuer public key")
	util.Log("Run client with this nonce as parameter: %s", util.B2HexS(nonce))
	util.WaitForEnter("When client is done creating the proof, press Enter to continue")

	proof, err := util.ReadProofFromFile(PROOF_PATH)
	util.ExitIfError("Failed to read proof from file", err)

	publicKeyBytes, err := util.HexS2B(issuer.PublicKey)
	util.ExitIfError("Error converting public key to bytes", err)

	result, err := verifyProof(nonce, publicKeyBytes, proof)
	util.Log("Result: %t, err: %s", result, err)

}

func createNonce() []byte {
	return []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
}

func verifyProof(nonce []byte, issuerPK []byte, proof *util.ZKProof) (bool, error) {

	identityHashBytes, err := util.HexS2B(proof.IdentityHash)
	if err != nil {
		return false, errors.Wrapf(err, "Error converting IdentityHash %s to bytes", proof.IdentityHash)
	}
	signedIdentityHashBytes, err := util.HexS2B(proof.SignedIdentityHash)
	if err != nil {
		return false, errors.Wrapf(err, "Error converting SignedIdentityHash %s to bytes", proof.SignedIdentityHash)
	}
	verified := util.Verify(issuerPK, identityHashBytes, signedIdentityHashBytes)
	if !verified {
		return false, errors.Errorf("Verification failed for signature on Identity Hash! issuerPK=%s data=%s sig=%s",
			util.B2HexS(issuerPK), proof.IdentityHash, proof.SignedIdentityHash)
	}

	verificationKey := util.ReadFileOrPanic(VERIFICATION_KEY_PATH)

	zkVerified, err := verifyZKProof(verificationKey, proof)
	if err != nil {
		return false, errors.Wrapf(err, "verifyZKProof() failed")
	}

	return zkVerified, nil

}

// TODO Impl over Orbs
func verifyZKProof(verificationKey []byte, proof *util.ZKProof) (bool, error) {

	// SendTransaction...
	// See https://github.com/orbs-network/contract-library-experiment/tree/master/contract

	//return true, nil
	return false, errors.New("not implemented")
}

func writeToBlockChain(nonce []byte, hashedId []byte, signedHashedId []byte, proof util.ZKProof, signedHashedIdAndNonce []byte) error {
	// TODO impl me

	return nil
}
