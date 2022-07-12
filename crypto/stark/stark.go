package stark

import (
	real_bytes "bytes"
	"math/big"

	rand "crypto/rand"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/crypto/weierstrass"
	"github.com/tendermint/tendermint/libs/bytes"
)

const (
	PrivKeyName = "tendermint/PrivKeyStark"
	PubKeyName  = "tendermint/PubKeyStark"

	KeyType     = "stark"
	PrivKeySize = 32
	PubKeySize  = 32
)

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
	return pv.pv.X.Bytes()
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

	return real_bytes.Equal(privKey.pv.X.Bytes(), p.Bytes())
}

type PubKey struct{ pb *PublicKey }

func (PubKey) TypeTag() string { return PubKeyName }

type Address = bytes.HexBytes

func pubKeyFromPrivate(pv *PrivKey) PubKey {
	return PubKey{
		pb: &pv.pv.PublicKey,
	}
}

func (p PubKey) MarshalCompressed() []byte {
	return weierstrass.MarshalCompressed(p.pb.Curve, p.pb.X, p.pb.Y)
}

func UnmarshalCompressed(curve weierstrass.Curve, data []byte) PubKey {
	x, y := weierstrass.UnmarshalCompressed(curve, data)
	pb := PublicKey{weierstrass.Stark(), x, y}

	p := PubKey{&pb}
	return p
}

func (p PubKey) Address() Address {
	b := p.pb.X.Bytes()
	bs := make([]byte, 32-len(b))
	br := append(bs, b...)
	return br
}

func (p PubKey) Bytes() []byte {

	b := p.pb.X.Bytes()
	bs := make([]byte, 32-len(b))
	br := append(bs, b...)
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
		return real_bytes.Equal(p.pb.X.Bytes(), otherEd.Bytes())
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
