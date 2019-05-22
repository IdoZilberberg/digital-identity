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

	coord0.SetString("0x2c3ff1734dd6a797306e8f632629524654933cc0be38e75c351be3258ad750ac",0)
	coord1.SetString("0x037811675568fe595a0ab517aebc83a7838f51f0cc8ceb25f872152a44512a73",0)
	bigintCoordsA := []*big.Int{&coord0, &coord1}
	a, _ := curve.MakeG1Point(bigintCoordsA, true)

	coord0.SetString("0x2b2ff65c75a083af10fda544309746e64a7e4cd9c97c699fde7db47748946491",0)
	coord1.SetString("0x257b2546c12ce0a78e4fabd4ed716bb3906676bc10e111e1918a5de3f3bb2f8c",0)
	coord2.SetString("0x146fe83c45d22eeffca5dc764fbde29c40bcb25b2a39f772289223628fe86b25",0)
	coord3.SetString("0x0f9db279b1d71dd7ee90303955b27d864a0b902dd2acd9d8d339bc3572ca5856",0)
	bigintCoordsB := []*big.Int{&coord0, &coord1, &coord2, &coord3}
	b, _ := curve.MakeG2Point(bigintCoordsB, true)

	coord0.SetString("0x30099ac4e0112344028b6f4b1cf9e5ec861539f9ea5bc1082e93a1ea924b574f",0)
	coord1.SetString("0x04d84160f38b193c5209fb299c8bec52e14ddd428897664a0c31e38a26a19f70",0)
	coord2.SetString("0x1855b8a6b6bb298ffe6c00c49efff5253673240ff769720862a486ec6f3943ae",0)
	coord3.SetString("0x0d50421e6d3b89aaad573f4a49673fc8153ead998697099ed1ab2cd8f2591503",0)
	bigintCoordsGamma := []*big.Int{&coord0, &coord1, &coord2, &coord3}
	gamma, _ := curve.MakeG2Point(bigintCoordsGamma, true)

	coord0.SetString("0x00f5ec11688882f16f114c7ba452e89a5905b44bc9a3363e1c809a43e55e3397",0)
	coord1.SetString("0x067ef11cff3c02bc954cab4a1fcda35da26bbb86292e6de32bc79a9edfdd9d5e",0)
	coord2.SetString("0x1d144848691b7a4430818c03bb4a0676384f5ceafa255ea7eef0c0a68776be78",0)
	coord3.SetString("0x1467672b53de9765c3f48242e87b309c7b680b56fd95e3400e1f2bb9b08dfadd",0)
	bigintCoordsDelta := []*big.Int{&coord0, &coord1, &coord2, &coord3}
	delta, _ := curve.MakeG2Point(bigintCoordsDelta, true)

	var abc [3]Point

	coord0.SetString("0x11cdddfacc6b0bf0bd8011af559888b1295f78378ba64ad7a71a5d34ca36bf4f",0)
	coord1.SetString("0x19a21b4107f7491e41ca840174274dd13d4b9bbde1b3b560405a870d67a64679",0)
	bigintCoordsABC1 := []*big.Int{&coord0, &coord1}
	abc[0], _ = curve.MakeG1Point(bigintCoordsABC1, true)

	coord0.SetString("0x1f95e54407e92855ed97557c21367e4ac6c2e5334536a399f6bb83f7a1e44074",0)
	coord1.SetString("0x171632f37bea7940bba99594f255d6234ef99606cf9743801fc739b311255ef8",0)
	bigintCoordsABC2 := []*big.Int{&coord0, &coord1}
	abc[1], _ = curve.MakeG1Point(bigintCoordsABC2, true)

	coord0.SetString("0x1d4437e82292f836f99e62a8fe9d2afdda1c4d52263f9642be9ae20e9c8334f9",0)
	coord1.SetString("0x2d5a34c13d764d173997f7f056737e83438d26b10924777db03ba70d631c49fd",0)
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
		tmp := vk.gammaABC[i + 1].Mul(&input[i])
		tmp2, _ := vkX.Add(tmp)
		vkX = tmp2
	}
	tmp3, _ := vkX.Add(vk.gammaABC[0])
	vkX = tmp3
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
	gT, _ := curve.PairingProduct(g1Points[:], g2Points[:])
	identity := curve.GetGTIdentity()
	result = gT.Equals(identity)
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
