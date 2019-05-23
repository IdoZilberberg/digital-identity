package main

import (
	"github.com/digital-identity/go/src/util"
	"github.com/pkg/errors"
	"os"
)

const ISSUER_PATH = "../issuer.json"
const PROOF_PATH = "../proof.json"
const VERIFICATION_KEY_PATH = "verification.key.txt"

const AUTHORIZER_PUBLIC_KEY = "92d469d7c004cc0b24a192d9457836bf38effa27536627ef60718b00b0f33152"
const AUTHORIZER_SECRET_KEY = "3b24b5f9e6b1371c3b5de2e402a96930eeafe52111bb4a1b003e5ecad3fab53892d469d7c004cc0b24a192d9457836bf38effa27536627ef60718b00b0f33152"

func main() {
	util.Log("AUTHORIZER START")

	nonce, err := util.HexS2B(os.Args[1])
	if err != nil {
		panic(err)
	}
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
	util.Log("\n\n\n*** VERIFIED SUCCESSFULLY? %t ***\n\n\n", result)

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

	util.Log("Identity Hash Bytes: %s", util.B2HexS(identityHashBytes))
	util.Log("Signed Identity Hash Bytes: %s", util.B2HexS(signedIdentityHashBytes))

	verified := util.Verify(issuerPK, identityHashBytes, signedIdentityHashBytes)
	if !verified {
		return false, errors.Errorf("Verification failed for signature on Identity Hash! issuerPK=%s data=%s sig=%s",
			util.B2HexS(issuerPK), proof.IdentityHash, proof.SignedIdentityHash)
	}

	//verificationKey := util.ReadFileOrPanic(VERIFICATION_KEY_PATH)

	zkVerified, err := verifyZKProof()
	if err != nil {
		return false, errors.Wrapf(err, "verifyZKProof() failed")
	}

	return zkVerified, nil

}

func verifyZKProof() (bool, error) {

	verifyZKProofWithGammaCli()

	return true, nil
}
