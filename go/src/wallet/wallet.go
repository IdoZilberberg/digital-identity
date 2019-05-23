package main

import (
	"encoding/json"
	"fmt"
	"github.com/digital-identity/go/src/util"
	"os"
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

	issuer, err := util.ReadIssuerFromFile(ISSUER_PATH)
	util.ExitIfError("Error reading issuer", err)
	util.Log("Read issuer")

	identityHash, err := util.CalculateHash([]byte(identity.String()))
	util.ExitIfError("Cannot compute hash for identity", err)

	skBytes, err := util.HexS2B(issuer.SecretKey)
	util.ExitIfError("Cannot convert secret key to bytes", err)

	util.Log("Signing with issuerSK: %s", issuer.SecretKey)
	signedIdentityHash, err := util.Sign(skBytes, identityHash)
	util.Log("Signed identity hash: %s, identityHash: %s", signedIdentityHash, util.B2HexS(identityHash))
	util.ExitIfError("Error signing", err)

	identityWithNonce := fmt.Sprintf("%s%s", identity.String(), nonce)
	identityWithNonceBytes := []byte(identityWithNonce)
	identityWithNonceHash, err := util.CalculateHash(identityWithNonceBytes)
	util.ExitIfError("Cannot compute hash for identity with nonce", err)

	util.Log("Reading proving key from %s", PROVING_KEY_PATH)
	provingKey := readProvingKeyFromFile(PROVING_KEY_PATH)
	//util.ExitIfError("Error reading proving keys", err)

	util.Log("Creating Proof...")
	proof, err := CreateProof(
		provingKey,
		identity.Secret,
		identity.String(),
		util.B2HexS(identityHash),
		util.TodayYYYYMMDD(),
		nonce,
		util.B2HexS(identityWithNonceHash),
		util.B2HexS(signedIdentityHash),
	)
	util.ExitIfError("Failed to create proof", err)

	util.WriteProofJson(proof, PROOF_PATH)
	util.Log("Proof: %s", proof)
	util.Log("Wrote proof to file, continue with Authorizer flow")

}

type Identity struct {
	Secret  string `json:"secret"`
	Name    string `json:"name"`
	Surname string `json:"surname"`
	DOB     string `json:"dob"`
}

func (i *Identity) String() string {
	return fmt.Sprintf("%s%s%s%s", i.Name, i.Surname, i.DOB, i.Secret)
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
	provingKey []byte,
	clientSecret string,
	identityString string, // A: ClientSecret+1980
	identityHash string, // B: 09873425098142708914725 // string
	today string, // 2019
	nonce string,
	identityWithNonceHash string, // string
	signedIdentityHash string, // string
) (*util.ZKProof, error) {

	// TODO Impl me

	return &util.ZKProof{
		A0:                    "",
		A1:                    "",
		A_p0:                  "",
		A_p1:                  "",
		B00:                   "",
		B01:                   "",
		B10:                   "",
		B11:                   "",
		B_p0:                  "",
		B_p1:                  "",
		C0:                    "",
		C1:                    "",
		C_p0:                  "",
		C_p1:                  "",
		H0:                    "",
		H1:                    "",
		K0:                    "",
		K1:                    "",
		IdentityHash:          identityHash,
		SignedIdentityHash:    signedIdentityHash,
		IdentityWithNonceHash: identityWithNonceHash,
	}, nil

	//return nil, errors.New("not implemented")
}
