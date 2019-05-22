package main

import (
	"encoding/json"
	"fmt"
	"github.com/digital-identity/go/src/util"
	"github.com/pkg/errors"
	"os"
)

func main() {
	util.Log("WALLET START")
	args := os.Args[1:]

	if len(args) == 0 {
		util.Log("Usage: <nonce>")
		os.Exit(1)
	}
	nonce := args[0]

	identity, err := readIdentityFromFile("../data/identity.json")
	util.ExitIfError("Error reading identity", err)

	issuer, err := util.ReadIssuerFromFile("../issuer.json")
	util.ExitIfError("Error reading issuer", err)

	identityHashBytes, err := util.S2B(identity.String())
	util.ExitIfError("Cannot convert identity to bytes", err)
	identityHash := util.SHA256(identityHashBytes)
	pkBytes, err := util.S2B(issuer.PrivateKey)
	util.ExitIfError("Cannot convert private key to bytes", err)
	signedIdentityHash, err := util.Sign(pkBytes, identityHash)
	util.Log("Signed identity: %s", signedIdentityHash)
	util.ExitIfError("Error signing", err)
	identityWithNonce := fmt.Sprintf("%s%s", identity.String(), nonce)

	identityWithNonceBytes, err := util.S2B(identityWithNonce)
	util.ExitIfError("Cannot convert identity with nonce to bytes", err)
	identityWithNonceHash := util.SHA256(identityWithNonceBytes)

	provingKey, err := readProvingKeyFromFile("../data/proving.keys")
	util.ExitIfError("Error reading proving keys", err)

	proof, err := CreateProof(
		util.B2S(*provingKey),
		identity.Secret,
		identity.String(),
		util.B2S(identityHash),
		util.TodayYYYYMMDD(),
		nonce,
		util.B2S(identityWithNonceHash),
		util.B2S(signedIdentityHash),
	)
	util.ExitIfError("Failed to create proof", err)
	util.WriteProofJson(proof)
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

func readProvingKeyFromFile(path string) (*[]byte, error) {
	input := util.ReadFileOrPanic(path)
	var value []byte
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func CreateProof(
	provingKey string,
	clientSecret string,
	identityString string, // A: ClientSecret+1980
	identityHash string, // B: 09873425098142708914725 // string
	today string, // 2019
	nonce string,
	hashedIdentityWithNonce string, // string
	signedIdentityHash string, // string
) (*util.ZKProof, error) {

	// TODO Impl me

	return nil, errors.New("not implemented")
}
