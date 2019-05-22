// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package verifier

import (
	"math/big"

	. "github.com/orbs-network/bgls/curves" // nolint: golint
)

// Verifier
type verifyingKeyStruct struct {
	a Point
	b Point
	gamma Point
	delta Point
	gammaABC [3]Point
}

type proof struct {
	a Point
	b Point
	c Point
}

func verifyingKey(curve CurveSystem) (vk verifyingKeyStruct) {
	var coord0 big.Int
	var coord1 big.Int
	var coord2 big.Int
	var coord3 big.Int

	coord0.SetString("0x000b33d9ad29a9b0d5efbf7dfae50b99cf281d743a2c1a2ab11f98f7db397d46",0)
	coord1.SetString("0x0a0882ed31e0e1a693aef33b8e340474c02fd4b0c181d22edf10d1f424affa73",0)
	bigintCoordsA := []*big.Int{&coord0, &coord1}
	a, _ := curve.MakeG1Point(bigintCoordsA, true)

	coord0.SetString("0x1dfffdda89034ae429c2728d7a0e84bc5c626341a0784b2e8096e3bdc17991eb",0)
	coord1.SetString("0x087b88affb2f79ffcb1ecce68437d0f87b2e7eec946ddab28fd6dd1ec44d0da7",0)
	coord2.SetString("0x0ffcb5e0eb532684ca67dc96ff637790e1aaf1a8c11f66f25cdcb1c24dcddde6",0)
	coord3.SetString("0x08ffa2a55ee7ce13b267e252a6819d15203547c82cf5176d59b5f9556a5850d4",0)
	bigintCoordsB := []*big.Int{&coord0, &coord1, &coord2, &coord3}
	b, _ := curve.MakeG2Point(bigintCoordsB, true)

	coord0.SetString("0x16df303edb03dc216eeebef9fb9b37d9aff584cc042183997597617580010c74",0)
	coord1.SetString("0x024b87109d56f6b2b6b89b285a0a069aa956f136a655c7b64d2477255ca7bf81",0)
	coord2.SetString("0x101f90e15abb7695f9a1cfe1bd74c9c7ebcaa8831714320e4d09d2e59b9b7939",0)
	coord3.SetString("0x00675d9ff132524cf4958cf53fa034ec25601c09a7408c878b468893d4822643",0)
	bigintCoordsGamma := []*big.Int{&coord0, &coord1, &coord2, &coord3}
	gamma, _ := curve.MakeG2Point(bigintCoordsGamma, true)

	coord0.SetString("0x0a07b61fc43a17e22edefb2a29702151f2766b1c0d95101997c6df86f1a405e7",0)
	coord1.SetString("0x192f088fb81ff76b3650ecef61732c74b904a14a502ef2c9a44adbddad9d7e08",0)
	coord2.SetString("0x2f22f5764cb39a5ae5662bbe96bda2b7c7707fd2c30bd1cc541846067c765a4a",0)
	coord3.SetString("0x08fc7f140b437b1e47243c81effa26ac5ddc7be705e4033226a94d1477372a36",0)
	bigintCoordsDelta := []*big.Int{&coord0, &coord1, &coord2, &coord3}
	delta, _ := curve.MakeG2Point(bigintCoordsDelta, true)

	var abc [3]Point

	coord0.SetString("0x108deb3b8220f45a52338177bba2a458bde8c6580a8823a2d7e04185e54a66c4",0)
	coord1.SetString("0x2f32ed947cc6f83e8741852634e4822e431c52eea2a3a54a0ccab5a8c918deb0",0)
	bigintCoordsABC1 := []*big.Int{&coord0, &coord1}
	abc[0], _ = curve.MakeG1Point(bigintCoordsABC1, true)

	coord0.SetString("0x0064197f6d66619300e9cf6ef7c3a03c44cc5f0955c2221053b3b65f09fe4622",0)
	coord1.SetString("0x23a00dce927a8af357bc98ac344f662468808e8958fe371ef3d204ca01a7b8a1",0)
	bigintCoordsABC2 := []*big.Int{&coord0, &coord1}
	abc[1], _ = curve.MakeG1Point(bigintCoordsABC2, true)

	coord0.SetString("0x26dd2c0208373e940c6342e9b9d9d04dde91f1e5de045fbe969864b4acc32640",0)
	coord1.SetString("0x071cf50e51ff5e468bf4aaf1d2d5ab10ac37862c9196c765ebb998bea7ba1505",0)
	bigintCoordsABC3 := []*big.Int{&coord0, &coord1}
	abc[2], _ = curve.MakeG1Point(bigintCoordsABC3, true)

	vk = verifyingKeyStruct{a: a, b: b, gamma : gamma, delta : delta, gammaABC : abc}
	return
}

func negate(curve CurveSystem, g1point Point) (result Point) {
	var altbnG1Q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	coords := g1point.ToAffineCoords()
	coords[1].Sub(altbnG1Q, coords[1])
	result, _ = curve.MakeG1Point(coords, false)
	return
}

func verify(curve CurveSystem, input [2]big.Int, proof proof) (result bool) {
	vk := verifyingKey(curve);
	bigintCoordsZero := []*big.Int{big.NewInt(0), big.NewInt(0)}
	vkX, _ := curve.MakeG1Point(bigintCoordsZero, true)
	for i := 0; i < len(input); i++ {
		vkX.Add(vk.gammaABC[i + 1].Mul(&input[i]))
	}
	vkX.Add(vk.gammaABC[0])
	var g1Points [4]Point
	g1Points[0] = proof.a
	g1Points[1] = negate(curve, vkX)
	g1Points[2] = negate(curve, proof.c)
	g1Points[3] = negate(curve, vk.a)
	var g2Points [4]Point
	g2Points[0] = proof.b
	g2Points[1] = vk.gamma
	g2Points[2] = vk.delta
	g2Points[3] = vk.b
	_, result = curve.PairingProduct(g1Points[:], g2Points[:])
	return
}

func VerifyProof(curve CurveSystem, a [2]big.Int, b [2][2]big.Int, c [2]big.Int, input [2]big.Int) (result bool) {
	var proof proof;

	coordsA := []*big.Int{&a[0], &a[1]}
	proof.a, _ = curve.MakeG1Point(coordsA, true)
	coordsB := []*big.Int{&b[0][0], &b[0][1],&b[1][0], &b[1][1]}
	proof.b, _ = curve.MakeG2Point(coordsB, true)
	coordsC := []*big.Int{&c[0], &c[1]}
	proof.c, _ = curve.MakeG1Point(coordsC, true)

	result = verify(curve, input, proof)
	return
}
