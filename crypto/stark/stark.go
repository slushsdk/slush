package stark

import (
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

func (privKey *PrivKey) Bytes() []byte {
	return privKey.pv.X.Bytes()
}

func (privKey *PrivKey) PubKey() crypto.PubKey {
	return privKey.PubKey()
}

func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	r, s, err := Sign(rand.Reader, privKey.pv, msg)
	if err != nil {
		panic(err)
	}
	return serializeSig(r, s), nil
}

func (privKey PrivKey) Equals(p PrivKey) bool {
	return privKey.pv.X.Cmp(p.pv.X) == 0
}

type PubKey struct{ PublicKey }

type Address = bytes.HexBytes

func (p PubKey) Address() Address {
	return p.X.Bytes()
}

func (p PubKey) Bytes() []byte {
	return p.Bytes()
}

func (p PubKey) VerifySignature(msg []byte, sig []byte) bool {
	r, s := deserializeSig(sig)
	return Verify(&p.PublicKey, msg, r, s)
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
