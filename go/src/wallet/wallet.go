package main

import (
	"encoding/json"
	"fmt"
	"github.com/digital-identity/go/src/util"
	"os"
	"strings"
	"time"
)

const PROOF_PATH = "../proof.json"
const IDENTITY_PATH = "identity.json"
const ISSUER_PATH = "../issuer.json"
const PROVING_KEY_PATH = "proving.key.txt"

func main() {
	util.Log("WALLET START")
	args := os.Args[1:]

	if len(args) == 0 {
		util.Log("Usage: <nonce>")
		os.Exit(1)
	}
	nonce := args[0]

	identity, err := readIdentityFromFile(IDENTITY_PATH)
	util.ExitIfError("Error reading identity", err)
	util.Log("Read identity")

	//issuer, err := util.ReadIssuerFromFile(ISSUER_PATH)
	util.ExitIfError("Error reading issuer", err)
	util.Log("Read issuer")

	identityHash, err := util.CalculateHash(identity.Secret, identity.Name, identity.DOB, "0")
	util.ExitIfError("Cannot compute hash for identity", err)
	//util.Log("Identity Hash: %s", identityHash)
	//skBytes, err := util.HexS2B(issuer.SecretKey)
	util.ExitIfError("Cannot convert secret key to bytes", err)

	//util.Log("Signing with issuerSK: %s", issuer.SecretKey)
	//signedIdentityHash, err := util.Sign(skBytes, identityHash)
	//util.Log("Signed identity hash: %s\nIdentityHash: %s", util.B2HexS(signedIdentityHash), util.B2HexS(identityHash))
	util.ExitIfError("Error signing", err)

	identityWithNonceHash, err := util.CalculateHash(identity.Secret, identity.Name, identity.DOB, nonce)
	util.ExitIfError("Cannot compute hash for identity with nonce", err)
	//util.Log("Identity+Nonce Hash: %s", identityWithNonceHash)
	//util.Log("Reading proving key from %s", PROVING_KEY_PATH)
	//provingKey := readProvingKeyFromFile(PROVING_KEY_PATH)
	//util.ExitIfError("Error reading proving keys", err)

	util.Log("Creating Proof...")

	identityHashParts := strings.Split(string(identityHash), ",")
	identityWithNonceHashParts := strings.Split(string(identityWithNonceHash), ",")

	millis := time.Now().UnixNano() / 1000000
	proofOutFile, err := CreateProof(
		identity.Secret,
		identity.Name,
		identity.DOB,
		"2019",
		identityHashParts[0],
		identityHashParts[1],
		nonce,
		identityWithNonceHashParts[0],
		identityWithNonceHashParts[1],
		fmt.Sprintf("%d", millis),
	)
	util.ExitIfError("Failed to create proof", err)

	//util.WriteProofJson(proof, PROOF_PATH)
	util.Log("*** Wrote proof to file %s, continue with Authorizer flow", proofOutFile)

}

type Identity struct {
	Secret string `json:"secret"`
	Name   string `json:"name"`
	DOB    string `json:"dob"`
}

func (i *Identity) String() string {
	return fmt.Sprintf("%s%s%s", i.Name, i.DOB, i.Secret)
}

func readIdentityFromFile(path string) (*Identity, error) {
	input := util.ReadFileOrPanic(path)
	var value Identity
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func readProvingKeyFromFile(path string) []byte {
	input := util.ReadFileOrPanic(path)
	return input
}

func CreateProof(
	clientSecret string,
	name string,
	birthYear string,
	currentYear string,
	hashedID0 string,
	hashedID1 string,
	nonce string,
	identityWithNonceHash0 string, // string
	identityWithNonceHash1 string, // string
	timestamp string, // string
) ([]byte, error) {

	args := fmt.Sprintf("%s %s %s %s %s %s %s %s %s",
		clientSecret, name, birthYear, hashedID0, hashedID1, nonce, identityWithNonceHash0, identityWithNonceHash1, timestamp)
	util.Log("*** GENERATING PROOF ***")
	util.Log("Args: %s", args)

	out, err := util.RunExternal("./generate_proof.sh", args)
	if err != nil {
		return nil, err
	}

	return out, nil
	//
	//
	//
	//
	//// TODO Impl me
	//
	//return &util.ZKProof{
	//	A0:                    "",
	//	A1:                    "",
	//	A_p0:                  "",
	//	A_p1:                  "",
	//	B00:                   "",
	//	B01:                   "",
	//	B10:                   "",
	//	B11:                   "",
	//	B_p0:                  "",
	//	B_p1:                  "",
	//	C0:                    "",
	//	C1:                    "",
	//	C_p0:                  "",
	//	C_p1:                  "",
	//	H0:                    "",
	//	H1:                    "",
	//	K0:                    "",
	//	K1:                    "",
	//	IdentityHash:          identityHash,
	//	SignedIdentityHash:    signedIdentityHash,
	//	IdentityWithNonceHash: identityWithNonceHash,
	//}, nil
	//
	////return nil, errors.New("not implemented")
}
