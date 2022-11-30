package stark

import (
	real_bytes "bytes"
	"fmt"
	"math/big"

	rand "crypto/rand"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/crypto/weierstrass"
	"github.com/tendermint/tendermint/internal/jsontypes"
	"github.com/tendermint/tendermint/libs/bytes"
)

const (
	PrivKeyName = "tendermint/PrivKeyStark"
	PubKeyName  = "tendermint/PubKeyStark"

	KeyType     = "stark"
	PrivKeySize = 32
	PubKeySize  = 32
)

func init() {
	jsontypes.MustRegister(PubKey{})
	jsontypes.MustRegister(PrivKey{})
}

var curve = weierstrass.Stark()

type PrivKey struct{ pv *PrivateKey }

func GenPrivKey() PrivKey {
	pv, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return PrivKey{pv: pv}
}

func randFieldElementFromSecret(
	c weierstrass.Curve, bs []byte,
) (k *big.Int, err error) {
	params := c.Params()
	// Note that for P-521 this will actually be 63 bits more than the
	// order, as division rounds down, but the extra bit is
	// inconsequential.
	b := make([]byte, params.BitSize/8+8) // TODO: use params.N.BitLen()
	b = (bs)

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenPrivKeyFromSecret(bs []byte) *PrivKey {
	c := weierstrass.Stark()
	k, _ := randFieldElementFromSecret(c, bs)

	pvt := new(PrivateKey)
	pvt.PublicKey.Curve = c
	pvt.D = k
	pvt.PublicKey.X, pvt.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return &PrivKey{pvt}
}

func (PrivKey) TypeTag() string { return PrivKeyName }

func (PrivKey) Type() string { return KeyType }

func (pv PrivKey) Bytes() []byte {

	return pv.pv.D.Bytes()
}

func (pv PrivKey) PubKey() crypto.PubKey {
	return pubKeyFromPrivate(&pv)

}

func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	r, s, err := Sign(rand.Reader, privKey.pv, msg)
	if err != nil {
		panic(err)
	}
	return serializeSig(r, s), nil
}

func (privKey PrivKey) Equals(p crypto.PrivKey) bool {
	if p.Type() != KeyType {
		return false
	}

	return real_bytes.Equal(privKey.Bytes(), p.Bytes())
}

type PubKey struct{ pb *PublicKey }

func (PubKey) TypeTag() string { return PubKeyName }

type Address = bytes.HexBytes

func pubKeyFromPrivate(pv *PrivKey) PubKey {
	return PubKey{
		pb: &pv.pv.PublicKey,
	}
}

//We modify MarshalCompressed so that we fit into 32 bytes, we can do this with 252 bits.
func (p PubKey) MarshalCompressed() []byte {
	if p.IsNil() {
		panic("can't marshall nil key")
	}
	curve := p.pb.Curve
	x := *p.pb.X
	y := p.pb.Y

	byteLen := (curve.Params().BitSize + 7) / 8
	compressed := make([]byte, byteLen)
	x.FillBytes(compressed)
	if compressed[0]&byte(128) == 128 {
		fmt.Sprintln("marshalling failed, 0th bit not empty.")
		panic("marshalling failed, 0th bit not empty.")

	} else {
		compressed[0] = byte(compressed[0] | byte(y.Bit(0)*128))
	}
	return compressed
}

func UnmarshalCompressed(curve weierstrass.Curve, data []byte) PubKey {

	x := new(big.Int)
	y := new(big.Int)

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != byteLen {
		// notest
		panic("marshalling failed, wrong byte len")

	}
	ybit := data[0] & 128
	data[0] = data[0] & 127
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[:])
	if x.Cmp(p) >= 0 {
		// notest
		panic("unmarshalling failed, x is greater than p")

	}
	if x.Cmp(big.NewInt(0)) == 0 {
		panic("x is 0")
	}
	// y² = x³ - 3x + b (mod p).
	y = curve.Params().Short(x)
	y = y.ModSqrt(y, p)
	if y == nil {
		// notest
		panic("unmarshalling failed, y does not exist")

	}
	fmt.Print(data[0], data[0]&byte(128))
	if byte(y.Bit(0)) != ybit {
		// notest
		y.Neg(y).Mod(y, p)
	}
	if !curve.IsOnCurve(x, y) {
		// notest
		panic("marshalling failed, x, y not on curve")

	}

	pb := PublicKey{weierstrass.Stark(), x, y}

	rp := PubKey{&pb}
	return rp
}

func (p PubKey) Address() Address {
	br := p.MarshalCompressed()
	return br
}

func (p PubKey) IsNil() bool {
	if p.pb == nil {
		return true
	}
	return false
}

func (p PubKey) Bytes() []byte {

	br := p.MarshalCompressed()
	return br
}

func (p PubKey) VerifySignature(msg []byte, sig []byte) bool {
	r, s := deserializeSig(sig)
	return Verify(p.pb, msg, r, s)
}

func (p PubKey) Equals(pb crypto.PubKey) bool {

	if pb.Type() != KeyType {
		return false
	}

	if otherEd, ok := pb.(PubKey); ok {
		return real_bytes.Equal(p.Bytes(), otherEd.Bytes())
	}
	return false

}

func (p PubKey) Type() string {
	return KeyType
}

func serializeSig(r *big.Int, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}

func deserializeSig(sig []byte) (r *big.Int, s *big.Int) {
	if len(sig) != 64 {
		panic("Invalid signature length")
	}

	chunked := utils.Split(sig, 32)

	rBytes := chunked[0]
	sBytes := chunked[1]

	r = new(big.Int).SetBytes(rBytes)
	s = new(big.Int).SetBytes(sBytes)
	return r, s
}
