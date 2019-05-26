// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package main

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/orbs-network/bgls/curves" // nolint: golint
	"github.com/orbs-network/orbs-contract-sdk/go/sdk/v1"
)

var PUBLIC = sdk.Export(VerifyProof)
var SYSTEM = sdk.Export(_init)

func _init() {
}

// Verifier
type verifyingKeyStruct struct {
	a        curves.Point
	b        curves.Point
	gamma    curves.Point
	delta    curves.Point
	gammaABC []curves.Point
}

type proof struct {
	a curves.Point
	b curves.Point
	c curves.Point
}

func verifyingKey(curve curves.CurveSystem) (vk verifyingKeyStruct) {
	alpha, _ := curve.MakeG2Point(parseBigIntArray("0x1df833a50fd818fa6a676b259d01311f81f1efc0c0d8af46a19c1c0b3615d783,0x1ba98993bbdd8b9b517d8547d6062d384adddaa184b8bee87a8dea364c10e677"), true)
	beta, _ := curve.MakeG2Point(parseBigIntArray("0x11cc654c1d2625fdec704da9aeac03c10844118178135bd7da5fa33b5ff35ed1,0x1c7283b668b57c051feb137201232b7bb8bdf135c6a2bcef37901aabb95166d5,0x0800d311b38e745806cc6f79ad161af740a2e47ab0cf85bcb0fa24bc71b222ef,0x0c322f0c83172ff25444572c7d4b2ef8485866404befe25a065f94fb00f86d4d"), true)
	gamma, _ := curve.MakeG2Point(parseBigIntArray("0x2742dbcb63e31d4a87ba28950f8c15e29803c3c922a8cd00074df8fb3a060366,0x0aa62ede64afca55f950ffd284d17f7c40bfed4504b59be9a2b5bdd3886e495a,0x1bdfed7c77bdf0354121a11bbe13ee32ef10c6c0e7d8325abbbce0653b628d04,0x2c728607dcfdc183ea534938c8b93c8e8e9004cefd9f30481d7318a830ae2104"), true)
	delta, _ := curve.MakeG2Point(parseBigIntArray("0x014cea764c176e53fe253b0568c65123096fde5e3bb608ddf33824abb46e0c70,0x129df1a296d3e0911308365af6cf3a47484ca80ced5adc57abe4dee1919764eb,0x099fd2cb9bf79af6b9001ccc4d24af24fc24f8ac6e2587789c63ae78e3f164b1,0x242efcb23d74f1059a911e5e2ba19eb8518b829b70c070ffe20050b4edd3b0b3"), true)
	var gammaABC [8]curves.Point
	gammaABC[0], _ = curve.MakeG2Point(parseBigIntArray("0x0ca91796de532ad9a791e93dcdfe54dd6322942abf17487ec3ef6dbbcd988d75,0x27dacfe9349ed9ec18b70019a92cdea7531d1dc99bec62178d367656842108e1"), true)
	gammaABC[1], _ = curve.MakeG2Point(parseBigIntArray("0x06d198cad61b77935de7dd0909ba32ccbbb59946a6af971d264360c67eaa22b3,0x1d859ea64476f16ff72af9cb297173a33144ab67b93d228e4b1756c548c1e0d5"), true)
	gammaABC[2], _ = curve.MakeG2Point(parseBigIntArray("0x06c2e088321447fe5f6cd33ca3ce8ddab921f95ec8d9e9d898a10e48b68440a1,0x1cc04670762a34d3cdbf3d79eb96bd54d8217cb43c0c407cb8085b66c5df0f4d"), true)
	gammaABC[3], _ = curve.MakeG2Point(parseBigIntArray("0x0e3e77e58fad444caebf2cc16e38e176fa7fc0629c57e39040b953f4d17170d5,0x2712cf7c09806e8a083e13249fb4d27f775dc07fa3e95b2520499fff837e90df"), true)
	gammaABC[4], _ = curve.MakeG2Point(parseBigIntArray("0x2c98cb620e174013b4c922b98c30daaa5c6ec9f63c2fabdd2bd75a51ac2c9a4a,0x25d8f91b317a3c21bb6debe11369a2ea2d1f117ed3892bae5daabe4a4f477eb9"), true)
	gammaABC[5], _ = curve.MakeG2Point(parseBigIntArray("0x1c0abd271b07bdbbeaff703a7f3096515cec6650553978e9aa41c2153faaf8c6,0x2ad76234d133d3d23c60ae0ccd74c60a8ca84c65f65818b535890937aa66ae36"), true)
	gammaABC[6], _ = curve.MakeG2Point(parseBigIntArray("0x05cc88ea2cf0b097fc8c093f439f46b23753fac312d5c5d61811dddd08e3b1ee,0x072c3ee06cf8b25eff85d0eecef8d23f7b2f01b244020166a07a52b6a930c091"), true)
	gammaABC[7], _ = curve.MakeG2Point(parseBigIntArray("0x157c1c102647345b1aeabc53c242943da7f5518acacc13b9275bef8ce7cfdcae,0x19755df2b0e6d0b0466ad67cb82e2a484422a0979f6a9d6f3a5bb1caedb5614f"), true)
	vk = verifyingKeyStruct{a: alpha, b: beta, gamma: gamma, delta: delta, gammaABC: gammaABC[:]}
	return
}
func negate(curve curves.CurveSystem, g1point curves.Point) (result curves.Point) {
	coords := g1point.ToAffineCoords()
	coords[1].Sub(curve.GetG1Q(), coords[1])
	result, _ = curve.MakeG1Point(coords, false)
	return
}

func verify(curve curves.CurveSystem, input []*big.Int, proof proof) (result bool) {
	vk := verifyingKey(curve)
	bigintCoordsZero := []*big.Int{big.NewInt(0), big.NewInt(0)}
	vkX, _ := curve.MakeG1Point(bigintCoordsZero, true)
	for i := 0; i < len(input); i++ {
		tmp := vk.gammaABC[i+1].Mul(input[i])
		tmp2, _ := vkX.Add(tmp)
		vkX = tmp2
	}
	tmp3, _ := vkX.Add(vk.gammaABC[0])
	vkX = tmp3
	var g1Points [4]curves.Point
	g1Points[0] = proof.a
	g1Points[1] = negate(curve, vkX)
	g1Points[2] = negate(curve, proof.c)
	g1Points[3] = negate(curve, vk.a)
	var g2Points [4]curves.Point
	g2Points[0] = proof.b
	g2Points[1] = vk.gamma
	g2Points[2] = vk.delta
	g2Points[3] = vk.b
	gT, _ := curve.PairingProduct(g1Points[:], g2Points[:])
	identity := curve.GetGTIdentity()
	result = gT.Equals(identity)
	return
}

func parseBigIntArray(input string) (result []*big.Int) {
	var inputStrings []string = strings.Split(input, ",")
	var output []*big.Int = make([]*big.Int, len(inputStrings))
	for i := 0; i < len(inputStrings); i++ {
		var a big.Int
		a.SetString(inputStrings[i], 0)
		output[i] = &a
	}
	return output
}

func Is_ok() bool {
	return true
}

//func CheckProof() uint32 {
//	var a [2]big.Int
//	a[0].SetString("0x09f50c87eebe68b181ea9772a125ac85efd91fb6e90209c1db8477873808d5d9", 0)
//	a[1].SetString("0x1379940536b0a9739866ecfb81f58db136199752dd35efcaee26adbc76218f7c", 0)
//	var b [2][2]big.Int
//	b[0][0].SetString("0x2f0c9a8098d33413550fef8561bb063300fc5ef5487de69d31d26854e789aaab", 0)
//	b[0][1].SetString("0x0cc94227faedb1ec9624eac3f692fd1162e27d77a82e512a8e313cc9307294c7", 0)
//	b[1][0].SetString("0x245720ccab66f9c32aceefd7b8be03b956aedf8a04c69453da8b36eec46a7a96", 0)
//	b[1][1].SetString("0x2cabed2c5711b16117f94b9db65a1a42d669a5c895d551fca43f84a8a22f1271", 0)
//	var c [2]big.Int
//	c[0].SetString("0x0daf9ac1b3d969873078d7b7de0f61f497b5bd6a4be0a25192b0127888f74b47", 0)
//	c[1].SetString("0x1d1ef5e4db1992e9a1abf73c8cd7260c16617f22fbd143b0788622073a9c348e", 0)
//	var input [7]big.Int
//	input[0].SetString("0x00000000000000000000000000000000000000000000000000000000000007e3", 0)
//	input[1].SetString("0x0000000000000000000000000000000072d67d19ceb15c63291cce17f12d3f3e", 0)
//	input[2].SetString("0x0000000000000000000000000000000062258940f07390a79bcdbc7e2f4c3124", 0)
//	input[3].SetString("0x0000000000000000000000000000000000000000000000000000000000016062", 0)
//	input[4].SetString("0x00000000000000000000000000000000b6964b2572dd8ca056313bd0d92cf572", 0)
//	input[5].SetString("0x000000000000000000000000000000006ffd538fd64a3e68c1fe2a8d4b389232", 0)
//	input[6].SetString("0x0000000000000000000000000000000000000000000000000000000000000001", 0)
//
//	if VerifyProof(curves.Altbn128, a, b, c, input[:]) {
//		return 1
//	} else {
//		return 0
//	}
//}

func VerifyProof(aStr string, bStr string, cStr string, inputStr string) uint32 {
	return VerifyProof2(curves.Altbn128, aStr, bStr, cStr, inputStr)
}

func VerifyProof2(curve curves.CurveSystem, aStr string, bStr string, cStr string, inputStr string) uint32 {
	fmt.Printf("\n\n\n\n\n\n\n Hellos \n\n\n\n\n\n")
	var proof proof
	////aStr= "0x075803fed276c64417f0a7ae76c1b2c5bc6d8efd7466c4e791ed8a5b442b2d9e,0x0e73a4c3932fc0a54c9f6e38c87067ecd40a27aec681a91e1f0a10ecb52f5516"
	////bStr = "0x1dd811ab5d50b91946cd1db42bc2a393484ecfbc8cd5920065ea94fde6d5ba55,0x1ae9b76c87c3b9cafbb4e1d39b4804b860a0ca1dafacdf208424bbe326c8cd2c,0x154086af81180da566c76d80a5a4b71d50f6f81c0c74bbb5565ba0def8e1b1ce,0x28da38e7ab834c8a6fc2176a393868bf5fbfabb0152c0444ee28873fe1773571"
	////cStr = "0x13b1cba32cd29f3568aa35212a22943085f0e40fa80f2719c3506e5a8a14310a,0x2d16fead425a374b3d6ded96491e8291a965d7f2afaf10f6ce3f0cfb3873c447"
	////inputStr = "0x000000000000000000000000000000000000000000000000000000000001bba1,0x0000000000000000000000000000000000000000000000000000000000000001"
	//
	//var a []*big.Int
	//a = parseBigIntArray(aStr)
	//fmt.Printf("\n\n\n\n\n\n\n %s \n\n\n\n\n\n", a)
	//proof.a, _ = curves.Altbn128.MakeG1Point(a, true)
	//
	//fmt.Printf("\n\n\n\n\n\n\n %s \n\n\n\n\n\n",proof.a)
	//
	//var b []*big.Int = parseBigIntArray(bStr)
	//proof.b, _ = curves.Altbn128.MakeG2Point(b, true)
	//
	//var c []*big.Int = parseBigIntArray(cStr)
	//proof.c, _ = curves.Altbn128.MakeG1Point(c, true)
	//var input []*big.Int = parseBigIntArray(inputStr)

	proof.a, _ = curve.MakeG1Point(parseBigIntArray(aStr), true)
	proof.b, _ = curve.MakeG2Point(parseBigIntArray(bStr), true)
	proof.c, _ = curve.MakeG1Point(parseBigIntArray(cStr), true)
	fmt.Printf("\n\n\n\n\n\n\n ODED1234567678909  %v \n\n\n\n\n\n", proof)

	var input []*big.Int
	input = parseBigIntArray(inputStr)
	fmt.Printf("\n\n\n\n\n\n\n ODED999999999  %v \n\n\n\n\n\n", input)
	result := verify(curve, input, proof)
	if result {
		return 1
	} else {
		return 0
	}
}

func main() {
	b := verifyingKey(curves.Altbn128)
	fmt.Printf("%s", b)
	a := VerifyProof("0x09f50c87eebe68b181ea9772a125ac85efd91fb6e90209c1db8477873808d5d9,0x1379940536b0a9739866ecfb81f58db136199752dd35efcaee26adbc76218f7c",
		"0x2f0c9a8098d33413550fef8561bb063300fc5ef5487de69d31d26854e789aaab,0x0cc94227faedb1ec9624eac3f692fd1162e27d77a82e512a8e313cc9307294c7,0x245720ccab66f9c32aceefd7b8be03b956aedf8a04c69453da8b36eec46a7a96,0x2cabed2c5711b16117f94b9db65a1a42d669a5c895d551fca43f84a8a22f1271",
		"0x0daf9ac1b3d969873078d7b7de0f61f497b5bd6a4be0a25192b0127888f74b47,0x1d1ef5e4db1992e9a1abf73c8cd7260c16617f22fbd143b0788622073a9c348e",
		"0x00000000000000000000000000000000000000000000000000000000000007e3,0x0000000000000000000000000000000072d67d19ceb15c63291cce17f12d3f3e,0x0000000000000000000000000000000062258940f07390a79bcdbc7e2f4c3124,0x0000000000000000000000000000000000000000000000000000000000016062,0x00000000000000000000000000000000b6964b2572dd8ca056313bd0d92cf572,0x000000000000000000000000000000006ffd538fd64a3e68c1fe2a8d4b389232,0x0000000000000000000000000000000000000000000000000000000000000001")
	fmt.Printf("%s", a)
}
