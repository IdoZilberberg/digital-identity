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
	a[0].SetString("0x075803fed276c64417f0a7ae76c1b2c5bc6d8efd7466c4e791ed8a5b442b2d9e",0)
	a[1].SetString("0x0e73a4c3932fc0a54c9f6e38c87067ecd40a27aec681a91e1f0a10ecb52f5516",0)
	var b [2][2]big.Int
	b[0][0].SetString("0x1dd811ab5d50b91946cd1db42bc2a393484ecfbc8cd5920065ea94fde6d5ba55",0)
	b[0][1].SetString("0x1ae9b76c87c3b9cafbb4e1d39b4804b860a0ca1dafacdf208424bbe326c8cd2c",0)
	b[1][0].SetString("0x154086af81180da566c76d80a5a4b71d50f6f81c0c74bbb5565ba0def8e1b1ce",0)
	b[1][1].SetString("0x28da38e7ab834c8a6fc2176a393868bf5fbfabb0152c0444ee28873fe1773571",0)
	var c [2]big.Int
	c[0].SetString("0x13b1cba32cd29f3568aa35212a22943085f0e40fa80f2719c3506e5a8a14310a",0)
	c[1].SetString("0x2d16fead425a374b3d6ded96491e8291a965d7f2afaf10f6ce3f0cfb3873c447",0)
	var input [2]big.Int
	input[0].SetString("0x000000000000000000000000000000000000000000000000000000000001bba1",0)
	input[1].SetString("0x0000000000000000000000000000000000000000000000000000000000000001",0)
	result := VerifyProof(Altbn128, a, b, c, input)
	fmt.Printf("Oded %t", result)
}
