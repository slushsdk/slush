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

func (PrivKey) TypeTag() string { return PrivKeyName }

func (PrivKey) Type() string { return PrivKeyName }

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

func (privKey PrivKey) Equals(p PrivKey) bool {
	return privKey.pv.X.Cmp(p.pv.X) == 0
}

type PubKey struct{ pb *PublicKey }

func (PubKey) TypeTag() string { return PubKeyName }

type Address = bytes.HexBytes

func pubKeyFromPrivate(pv *PrivKey) PubKey {
	return PubKey{
		pb: &pv.pv.PublicKey,
	}
}

func (p PubKey) Address() Address {
	return p.pb.X.Bytes()
}

func (p PubKey) Bytes() []byte {
	return p.pb.X.Bytes()
}

func (p PubKey) VerifySignature(msg []byte, sig []byte) bool {
	r, s := deserializeSig(sig)
	return Verify(p.pb, msg, r, s)
}

func (p PubKey) Equals(pb crypto.PubKey) bool {

	if pb.Type() != "tendermint/PubKeyStark" {
		return false
	}

	if otherEd, ok := pb.(PubKey); ok {
		return real_bytes.Equal(p.pb.X.Bytes(), otherEd.Bytes())
	}
	return false

}

func (p PubKey) Type() string {
	return PubKeyName
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
