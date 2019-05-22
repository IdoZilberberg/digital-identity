package util

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"
	"time"
)

type Issuer struct {
	Name       string `json:"issuer_name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

func ReadIssuerFromFile(path string) (*Issuer, error) {
	input := ReadFileOrPanic(path)
	var value Issuer
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func WaitForEnter(output string) {
	Log(output)
	buf := bufio.NewReader(os.Stdin)
	buf.ReadBytes('\n')
}

func Log(a ...interface{}) {
	fmt.Println(a)
}

func B2S(input []byte) string {
	return hex.EncodeToString(input)
}

func S2B(input string) ([]byte, error) {
	bytes, err := hex.DecodeString(input)
	if err != nil {
		return nil, errors.Wrapf(err, "S2B cannot convert string %s to bytes: %s")
	}
	return bytes, nil
}

func SHA256(data ...[]byte) []byte {
	s := sha256.New()
	for _, d := range data {
		s.Write(d)
	}
	return s.Sum(nil)
}

func Sign(privateKey []byte, data []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private Key is nil")
	}
	signedData := ed25519.Sign([]byte(privateKey), data)
	return signedData, nil
}

func Verify(publicKey []byte, data []byte, sig []byte) bool {
	return ed25519.Verify(publicKey, data, sig)
}

func ReadFileOrPanic(path string) []byte {
	input, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Cannot read file %s: %s", path, err))
	}
	return input
}

func ExitIfError(msg string, err error) {
	if err != nil {
		Log("%s: %s", msg, err)
		os.Exit(1)
	}
}

func TodayYYYYMMDD() string {
	return time.Now().Format("yyyy-MM-dd")
}
