// Copyright (C) 2018 Authors
// distributed under Apache 2.0 license

package verifier

import (
	"github.com/orbs-network/bgls/curves" // nolint: golint
	"math/big"
	"strings"
)

// Verifier
type verifyingKeyStruct struct {
	a curves.Point
	b curves.Point
	gamma curves.Point
	delta curves.Point
	gammaABC []curves.Point
}

type proof struct {
	a curves.Point
	b curves.Point
	c curves.Point
}

func verifyingKey(curve curves.CurveSystem) (vk verifyingKeyStruct) {
	alpha, _ := curve.MakeG1Point(parseBigIntArray("0x1b898d5d287cdea03cbb37db4101e778689129e830ac8385ee10bb67087848d9,0x298bc3069c705e5656939d10aa14e8cf201dece232ca1b3deb67356e72b162ed"), true)
	beta, _ := curve.MakeG2Point(parseBigIntArray("0x2c4ab27b932fa41873818a2007cf891a394521e75f6c899dd2c78dca7cb3c771,0x1ba5f4fda81b8de1a6d2cd653bd1417d278aca74d229430174749ab4de88b6ec,0x2bfd07986a0692f8500d4ff3b34d01fd08e6f6a8a425c7e48dfa2e062418d2be,0x2d2cce565d3c2cb8c2dd0139b7c70449cccb080277482957be57ae7462598f88"), true)
	gamma, _ := curve.MakeG2Point(parseBigIntArray("0x22d4cd7ad84cddf13011c48e0045f2afcda8de893268d42cd69f624044de2fab,0x0e3b99bf23e5f827b2ebd312143b3629af984d809e0f389c08899cb5ab11cbfc,0x16b6ccf92427c394554b978fc573b3aacb2d90f79674c955eaeb3272589a37d6,0x06df63fd2a3a8067793976e2bea82545467408d30e19457b1d29d33097e60f85"), true)
	delta, _ := curve.MakeG2Point(parseBigIntArray("0x2608690fd1545b7d8cd8dd6e3565a0302a0c1718ac3aa9b9225c43edc068af4f,0x1f35cb5c2b45edd34a4a4ad85a4adbd926b902d586d05d0dba28cbb962a8fc01,0x2e2fec8e663190635e138e674acc7accb887ebe529d946612e4cc6b7e78925ac,0x2479317e6d21868d6dd50ee5fb8e130d741abbbc229b8f1a7efd53fc0925fbe0"), true)
	var gammaABC [8]curves.Point
	gammaABC[0], _ = curve.MakeG1Point(parseBigIntArray("0x2a9214673bd588570d3521ea417c1ca17be5b4986a5a9d700e7a29affe119fed,0x2d16daa552d88e7d0e3a23d796da057dbca9f6aece7314f4c8a0841486356cdb"), true)
	gammaABC[1], _ = curve.MakeG1Point(parseBigIntArray("0x0b4b6a11e724545e4e1271bc043c1233d7bc302e655e08d36ac1213698e045dc,0x12b2160cc76eee9eea176a78679bcdcc67bf43421dea11e88eec38f91b72fffb"), true)
	gammaABC[2], _ = curve.MakeG1Point(parseBigIntArray("0x2486a5caf131019d50c60224d383aaafa391194f1c6e6345035548a5beb34273,0x08f68989a8d494fea9089ae64487be17f294c6a69308a5504e56d5e67be30ff3"), true)
	gammaABC[3], _ = curve.MakeG1Point(parseBigIntArray("0x170eaf02379fcaef96a4222688e16e7d7e02808f6b92f0fe07bd63d21b0c57f7,0x080ecf902737cc99b8aabe118c7683efd53218e1f80d927ffd60cf017679089a"), true)
	gammaABC[4], _ = curve.MakeG1Point(parseBigIntArray("0x0286703fcb99f3f05a67e60a78cfb8b9d0e95ac648c3935c30406fa9793b6d6c,0x1397e6ce9e54ec8130958478d72db8fcbc31911671ce1acb9802fef433b07335"), true)
	gammaABC[5], _ = curve.MakeG1Point(parseBigIntArray("0x2fab815e8617c2f1e1ee10b6c52b35a3f5a458ac6b59dbb75b1673d2bdb64f28,0x2a90ef650fb83364fe3f300396920f7a563a8720cedc6835f48772639016cec3"), true)
	gammaABC[6], _ = curve.MakeG1Point(parseBigIntArray("0x02e1da9e5843a907b92f1381b5aa23de999995149494cd34a2dd05e9ad1fc2d5,0x1832039e9dafe9a7764c1819e5b75475799f39e69174ed19b5b9a398bd007f3a"), true)
	gammaABC[7], _ = curve.MakeG1Point(parseBigIntArray("0x13b76a282a3ebc245282eb682a471e7eddc9ca6d45c637369ae4611eaa0a4edd,0x136f3da91d8aa3993378901836a855622a23abab79da213fef5c46b22bd235d0"), true)
	vk = verifyingKeyStruct{a: alpha, b: beta, gamma : gamma, delta : delta, gammaABC : gammaABC[:]}
	return
}

func negate(curve curves.CurveSystem, g1point curves.Point) (result curves.Point) {
	coords := g1point.ToAffineCoords()
	coords[1].Sub(curve.GetG1Q(), coords[1])
	result, _ = curve.MakeG1Point(coords, false)
	return
}

func verify(curve curves.CurveSystem, input []big.Int, proof proof) (result bool) {
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

func VerifyProof(curve curves.CurveSystem, a [2]big.Int, b [2][2]big.Int, c [2]big.Int, input []big.Int) (result bool) {
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

func parseBigIntArray(input string) (result []*big.Int) {
	var inputStrings []string = strings.Split(input, ",")
	var output []*big.Int = make([]*big.Int, len(inputStrings));
	for i := 0; i < len(inputStrings); i++ {
		var a big.Int;
		a.SetString(inputStrings[i], 0)
		output[i] = &a
	}
	return output
}