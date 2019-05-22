package main

import (
	"github.com/digital-identity/go/src/util"
	"github.com/pkg/errors"
)

func main() {
	util.Log("AUTHORIZER START")

	nonce := createNonce()
	issuer, err := util.ReadIssuerFromFile("../issuer.json")
	util.ExitIfError("Error reading issuer", err)

	util.Log("Successfully read issuer public key")
	util.Log("Generated nonce: %s")
	util.Log("Run client with this nonce as parameter: %s", util.B2S(nonce))
	util.WaitForEnter("When client is done creating the proof, press Enter to continue")

	proof, err := util.ReadProofFromFile("../proof.json")
	util.ExitIfError("Failed to read proof from file", err)

	publicKeyBytes, err := util.S2B(issuer.PublicKey)
	util.ExitIfError("Error converting public key to bytes", err)

	result, err := verifyProof(nonce, publicKeyBytes, proof)
	util.Log("Result: %s, err: %s", result, err)

}

func createNonce() []byte {
	return []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
}

func verifyProof(nonce []byte, issuerPK []byte, proof *util.ZKProof) (bool, error) {

	identityHashBytes, err := util.S2B(proof.IdentityHash)
	if err != nil {
		return false, errors.Wrapf(err, "Error converting IdentityHash %s to bytes", proof.IdentityHash)
	}
	signedIdentityHashBytes, err := util.S2B(proof.SignedIdentityHash)
	if err != nil {
		return false, errors.Wrapf(err, "Error converting SignedIdentityHash %s to bytes", proof.SignedIdentityHash)
	}
	verified := util.Verify(issuerPK, identityHashBytes, signedIdentityHashBytes)
	if !verified {
		return false, errors.New("Verification failed for signature on Identity Hash!")
	}

	verificationKey := util.ReadFileOrPanic("verification.key.txt")

	zkVerified, err := verifyZKProof(verificationKey, proof)
	if err != nil {
		return false, errors.Wrapf(err, "verifyZKProof() failed")
	}

	return zkVerified, nil

}

// TODO Over Orbs?
func verifyZKProof(verificationKey []byte, proof *util.ZKProof) (bool, error) {

	// SendTransaction...

	return false, errors.New("not implemented")
}

func writeToBlockChain(nonce []byte, hashedId []byte, signedHashedId []byte, proof util.ZKProof, signedHashedIdAndNonce []byte) error {
	// TODO impl me

	return nil
}
