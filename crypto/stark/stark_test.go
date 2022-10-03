package stark_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/stark"
	"github.com/tendermint/tendermint/crypto/weierstrass"
)

// invertible implements fast inverse in GF(N).
type invertible interface {
	// Inverse returns the inverse of k mod Params().N.
	Inverse(k *big.Int) *big.Int
}

// A combinedMult implements fast combined multiplication for
// verification.
type combinedMult interface {
	// CombinedMult returns [s1]G + [s2]P where G is the generator.
	CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int)
}

func TestGenPrivKey(t *testing.T) {
	pv := stark.GenPrivKey()
	require.LessOrEqual(t, len(pv.Bytes()), 32)
}

func TestSign(t *testing.T) {
	pv := stark.GenPrivKey()
	msg := []byte("hello world")
	sig, _ := pv.Sign(msg)
	require.Equal(t, len(sig), 64)
	fmt.Println("private key :", big.NewInt(0).SetBytes(pv.Bytes()))
	fmt.Println("public key x:", big.NewInt(0).SetBytes(pv.PubKey().Bytes()[:32]))
	fmt.Println("public key y:", big.NewInt(0).SetBytes(pv.PubKey().Bytes()[32:]))
	fmt.Println("sig r:", big.NewInt(0).SetBytes(sig[:32]))
	fmt.Println("sig s:", big.NewInt(0).SetBytes(sig[32:]))
	fmt.Println("msg :", hashToInt(crypto.Checksum(msg), weierstrass.Stark()))
	fmt.Println("verifying our signature:", pv.PubKey().VerifySignature(msg, sig))
	pub := (pv.MakeFull().PublicKey)
	fmt.Println("local verification:", verify(&pub, weierstrass.Stark(), crypto.Checksum(msg), big.NewInt(0).SetBytes(sig[:32]), big.NewInt(0).SetBytes(sig[32:])))
	fmt.Println("local verification:", stark.Verify(&pub, crypto.Checksum(msg), big.NewInt(0).SetBytes(sig[:32]), big.NewInt(0).SetBytes(sig[32:])))

	fmt.Println()
	// // msg2 := big.NewInt(4321).Bytes()
	// // sig3, _ := stark.SignECDSA(msg)
	// require.Equal(t, len(sig), 64)
	// fmt.Println("private key :", big.NewInt(0).SetBytes(pv.Bytes()))
	// fmt.Println("public key x:", big.NewInt(0).SetBytes(pv.PubKey().Bytes()[:32]))
	// fmt.Println("public key y:", big.NewInt(0).SetBytes(pv.PubKey().Bytes()[32:]))
	// fmt.Println("sig r:", big.NewInt(0).SetBytes(sig[:32]))
	// fmt.Println("sig s:", big.NewInt(0).SetBytes(sig[32:]))
	// fmt.Println("msg :", big.NewInt(0).SetBytes(crypto.Checksum(msg)))
	// // fmt.Println()

	hashint := (pedersen.Digest(big.NewInt(4321), big.NewInt(0)))
	hash := hashint.Bytes()
	pub2x, _ := big.NewInt(0).SetString("1628448741648245036800002906075225705100596136133912895015035902954123957052", 10)
	pubmarshalled := append([]byte{0x3}, pub2x.Bytes()...)
	pub2x, pub2y := weierstrass.UnmarshalCompressed(weierstrass.Stark(), pubmarshalled)

	fmt.Println("  ")
	fmt.Println("publickey x", pub2x)
	fmt.Println("publickey y", pub2y)

	// fmt.Println(pub2y)
	fmt.Println("hash", hashint)
	publicKey := stark.PublicKey{weierstrass.Stark(), pub2x, pub2y}

	fmt.Println("Is on curvel:", weierstrass.Stark().IsOnCurve(pub2x, pub2y))

	sigr, _ := big.NewInt(0).SetString("1225578735933442828068102633747590437426782890965066746429241472187377583468", 10)
	sigs, _ := big.NewInt(0).SetString("3568809569741913715045370357918125425757114920266578211811626257903121825123", 10)
	fmt.Println("Sigr", sigr)
	fmt.Println("Sigs", sigs)
	fmt.Println("N   ", weierstrass.Stark().Params().N)

	res := verify(&publicKey, weierstrass.Stark(), hash, sigr, sigs)
	res2 := verify2(&publicKey, weierstrass.Stark(), hash, sigr, sigs)
	res3 := verify3(&publicKey, weierstrass.Stark(), hash, sigr, sigs)

	fmt.Println("Verified :", res)
	fmt.Println("Verified2:", res2)
	fmt.Println("Verified3:", res3)

}

func verify(
	pub *stark.PublicKey, c weierstrass.Curve, hash []byte, r, s *big.Int,
) bool {
	// SEC 1, Version 2.0, Section 4.1.4
	e := big.NewInt(0).SetBytes(hash)
	f := hashToInt(hash, weierstrass.Stark())
	fmt.Println("message int", e)
	fmt.Println("message int2", f)

	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		// XXX: The following should be removed if more curves are added
		// that are invertible.
		// notest
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s, N)
	}

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p

	var xadd, yadd, xmin, ymin *big.Int
	if opt, ok := c.(combinedMult); ok {
		// XXX: The following should be removed if more curves are added
		// that support a combined multiplication operation.
		// notest
		xadd, yadd = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
		xmin, ymin = opt.CombinedMult(pub.X, big.NewInt(0).Mul(pub.Y, big.NewInt(-1)), u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(u1.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
		xadd, yadd = c.Add(x1, y1, x2, y2)
		xmin, ymin = c.Add(x1, y1, x2, big.NewInt(0).Mul(big.NewInt(-1), y2))
	}

	if xadd.Sign() == 0 && yadd.Sign() == 0 {
		// notest
		if xmin.Sign() == 0 && ymin.Sign() == 0 {
			return false
		}
		xmin.Mod(xmin, N)

		return (xmin.Cmp(r) == 0)
	}

	if xmin.Sign() == 0 && ymin.Sign() == 0 {
		xadd.Mod(xadd, N)

		return (xadd.Cmp(r) == 0)
	}

	xadd.Mod(xadd, N)
	xmin.Mod(xmin, N)

	return (xadd.Cmp(r) == 0) || (xmin.Cmp(r) == 0)
}

func verify2(
	pub *stark.PublicKey, c weierstrass.Curve, hash []byte, r, s *big.Int,
) bool {
	// SEC 1, Version 2.0, Section 4.1.4
	e := big.NewInt(0).SetBytes(hash)
	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		// XXX: The following should be removed if more curves are added
		// that are invertible.
		// notest
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s, N)
	}

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		// XXX: The following should be removed if more curves are added
		// that support a combined multiplication operation.
		// notest
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(u1.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
		x, y = c.Add(x1, y1, x2, y2.Mul(big.NewInt(-1), y2))
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		// notest
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func verify3(
	pub *stark.PublicKey, c weierstrass.Curve, hash []byte, r, s *big.Int,
) bool {
	// SEC 1, Version 2.0, Section 4.1.4

	P := weierstrass.Stark().Params().P
	e := big.NewInt(0).SetBytes(hash)
	var w *big.Int
	N := c.Params().N
	if in, ok := c.(invertible); ok {
		// XXX: The following should be removed if more curves are added
		// that are invertible.
		// notest
		w = in.Inverse(s)
	} else {
		w = new(big.Int).ModInverse(s, N)
	}

	u1 := e.Mul(e, big.NewInt(1))
	u1.Mod(u1, N)
	u2 := w.Mul(r, big.NewInt(1))
	u2.Mod(u2, N)

	// Check if implements S1*g + S2*p
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		// XXX: The following should be removed if more curves are added
		// that support a combined multiplication operation.
		// notest
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(e.Bytes())
		fmt.Println("message:", e)
		fmt.Println("zG", big.NewInt(0).Sub(x1, big.NewInt(0).Mul(big.NewInt(1), P)))

		x2, y2 := c.ScalarMult(pub.X, pub.Y, r.Bytes())
		fmt.Println("rQ", big.NewInt(0).Sub(x2, P))
		x, y = c.Add(x1, y1, x2, big.NewInt(0).Mul(big.NewInt(-1), y2))
		fmt.Println("sumx", x)
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		// notest
		return false
	}
	x.Mod(x, N)

	rmarsh := append([]byte{0x3}, r.Bytes()...)
	newrx, newry := weierstrass.UnmarshalCompressed(weierstrass.Stark(), rmarsh)

	newrx, newry = c.ScalarMult(newrx, newry, s.Bytes())
	fmt.Println("sR", big.NewInt(0).Sub(newrx, P))

	// newrx.Mod(newrx, N)
	return x.Cmp(newrx) == 0
}

func TestGetPublicKey(t *testing.T) {
	pv := stark.GenPrivKey()
	pb := pv.PubKey()
	require.Equal(t, len(pb.Bytes()), 64)
}

func TestAddress(t *testing.T) {
	pv := stark.GenPrivKey()
	pb := pv.PubKey()
	require.Equal(t, len(pb.Address()), 32)
}

func TestSignAndVerify(t *testing.T) {
	pv := stark.GenPrivKey()
	pb := pv.PubKey()

	msg := []byte("hello world")
	sig, _ := pv.Sign(msg)

	pb.VerifySignature(msg, sig)
}

func TestMarshalling(t *testing.T) {
	pv := stark.GenPrivKey()
	pb := pv.PubKey()

	pbo := stark.UnmarshalCompressedStark(weierstrass.Stark(), pb.Bytes())
	pb2 := pbo.MarshalCompressedStark()
	require.Equal(t, pb.Bytes(), pb2.Bytes())

}

func hashToInt(hash []byte, c weierstrass.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
