package util

import (
	"encoding/json"
	"io/ioutil"
)

// Zokrates Proof, see https://github.com/jstoxrocky/zksnarks_example

/*
Example:

A = 0x1628f3170cc16d40aad2e8fa1ab084f542fcb12e75ce1add62891dd75ba1ffd7, 0x11b20d11a0da724e41f7e2dc4d217b3f068b4e767f521a9ea371e77e496cc54
A_p = 0x1a4406c4ab38715a6f7624ece480aa0e8ca0413514d70506856af0595a853bc3, 0x2553e174040723a6bf5ea2188d2a1429bb01b13084c4af5b51701e6077716980
B = [0x27c9878700f09edc60cf23d3fb486fe50726f136ff46ad48653a3e7254ae3020, 0xe35b33188dc2f47618248e4f12a97026c3acdef9b4d021bf94e7b6d9e8ffbb6], [0x64cf25d53d57e2931d58d22fe34122fa12def64579c02d0227a496f31678cf8, 0x26212d004463c9ff80fc65f1f32321333b90de63b6b35805ef24be8b692afb28]
B_p = 0x175e0abe73317b738fd5e9fd1d2e3cb48124be9f7ae8080b8dbe419b224e96a6, 0x85444b7ef6feafa8754bdd3ca0be17d245f13e8cc89c37e7451b55555f6ce9d
C = 0x297a60f02d72bacf12a58bae75d4f330bed184854c3171adc6a65bb708466a76, 0x16b72260e7854535b0a821dd41683a28c89b0d9fcd77d36a157ba709996b490
C_p = 0x29ea33c3da75cd937e86aaf6503ec67d18bde775440da90a492966b2eb9081fe, 0x13fcc4b019b05bc82cd95a6c8dc880d4da92c53abd2ed449bd393e5561d21583
H = 0x2693e070bade67fb06a55fe834313f97e3562aa42c46d33c73fccb8f9fd9c2de, 0x26415689c4f4681680201c1975239c8f454ac4b2217486bc26d92e9dcacb58d7
K = 0x11afe3c25ff3821b8b42fde5a85b734cf6000c4b77ec57e08ff5d4386c60c72a, 0x24174487b1d642e4db86689542b8d6d9e97ec56fcd654051e96e36a8b74ea9ef

Stored in JSON as:

A0, A1, A_p0, A_p1, B00,B01,B10,B11, B_p0, B_p1, C0, C1, C_p0, C_p1, H0, H1, K0, K1

*/

type ZKProof struct {
	A0                    string `json:"A0"`
	A1                    string `json:"A1"`
	A_p0                  string `json:"A_p0"`
	A_p1                  string `json:"A_p1"`
	B00                   string `json:"B00"`
	B01                   string `json:"B01"`
	B10                   string `json:"B10"`
	B11                   string `json:"B11"`
	B_p0                  string `json:"B_p0"`
	B_p1                  string `json:"B_p1"`
	C0                    string `json:"C0"`
	C1                    string `json:"C1"`
	C_p0                  string `json:"C_p0"`
	C_p1                  string `json:"C_p1"`
	H0                    string `json:"H0"`
	H1                    string `json:"H1"`
	K0                    string `json:"C0"`
	K1                    string `json:"K1"`
	IdentityHash          string `json:"identity_hash"`
	SignedIdentityHash    string `json:"signed_identity_hash"`
	IdentityWithNonceHash string `json:"identity_with_nonce_hash"`
}

func ReadProofFromFile(path string) (*ZKProof, error) {
	input := ReadFileOrPanic(path)
	var value ZKProof
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func MarshalKeys(keys map[string]string) ([]byte, error) {
	return json.MarshalIndent(keys, "", "  ")
}

func WriteProofJson(proof *ZKProof) error {
	proofMap := make(map[string]string)
	proofMap["A0"] = proof.A0
	proofMap["A1"] = proof.A1
	proofMap["A_p0"] = proof.A_p0
	proofMap["A_p1"] = proof.A_p1
	proofMap["B00"] = proof.B00
	proofMap["B01"] = proof.B01
	proofMap["B10"] = proof.B10
	proofMap["B11"] = proof.B11
	proofMap["B_p0"] = proof.B_p0
	proofMap["B_p1"] = proof.B_p1
	proofMap["C0"] = proof.C0
	proofMap["C1"] = proof.C1
	proofMap["C_p0"] = proof.C_p0
	proofMap["C_p1"] = proof.C_p1
	proofMap["H0"] = proof.H0
	proofMap["H1"] = proof.H1
	proofMap["K0"] = proof.K0
	proofMap["K1"] = proof.K1
	proofMap["IdentityHash"] = proof.IdentityHash
	proofMap["SignedIdentityHash"] = proof.SignedIdentityHash
	proofMap["IdentityWithNonceHash"] = proof.IdentityWithNonceHash

	bytes, err := MarshalKeys(proofMap)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("../proof.json", bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}
