package verifier

import (
	"fmt"
	"math/big"
	"testing"

	. "github.com/orbs-network/bgls/curves" // nolint: golint
)

func TestHashProof(t *testing.T) {
	//func VerifyProof(curve CurveSystem, a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, input [2]*big.Int,) (result bool) {
	var a [2]big.Int
	a[0].SetString("0x08b97a67a0998889aa30325f3640c0bedbc190d199c3a9fa1123e6c82e4a2050",0)
	a[1].SetString("0x26c6ae7d0bb857e3bd1576aa29509e0296b4a34e7bc041b14ffa28de77473975",0)
	var b [2][2]big.Int
	b[0][0].SetString("0x2b357c899d1934e5b1efc41f6b7bf48dbd55c4a37738050af45a9e51bcad469b",0)
	b[0][1].SetString("0x077be5909d0ecf4d2d0ad3f8fa0293da72ffecbaf6cfe136f3695028eed2e5fb",0)
	b[1][0].SetString("0x2a9168b7e3801690ba0e74df9fdff0c621232f8fad49e03a7d7e57e9fb266b6c",0)
	b[1][1].SetString("0x0eb8eb54b3e0a0633b49973bdb7a3ab393422700bf9a14a712affb6c0f055270",0)
	var c [2]big.Int
	c[0].SetString("0x05cfc2cccf037a6f929f37b5669fead90311bfe49b058f3affcc23ebdb21d1e5",0)
	c[1].SetString("0x00ae83bebd4f48bbc9a3d70c1d527cf4058f06186941d867a8111d61a5393d20",0)
	var input [2]big.Int
	input[0].SetString("0x00000000000000000000000000000000c6481e22c5ff4164af680b8cfaa5e8ed",0)
	input[1].SetString("0x000000000000000000000000000000003120eeff89c4f307c4a6faaae059ce10",0)
	result := VerifyProof(Altbn128, a, b, c, input)
	fmt.Printf("Oded %t", result)
}
