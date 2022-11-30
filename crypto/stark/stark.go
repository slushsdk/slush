package stark

import (
	real_bytes "bytes"
	"errors"
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
	PubKeySize  = 64
)

func init() {
	jsontypes.MustRegister(PubKey{})
	jsontypes.MustRegister(PrivKey{})
}

var curve = weierstrass.Stark()

type PrivKey []byte //struct { pv *PrivateKey }

func GenPrivKey() PrivKey {
	pv, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return PrivKey(pv.D.Bytes())
}

func (PrivKey) TypeTag() string { return PrivKeyName }

func (PrivKey) Type() string { return KeyType }

func (pv PrivKey) Bytes() []byte {

	return []byte(pv)
}

func (pv PrivKey) PubKey() crypto.PubKey {
	return pubKeyFromPrivate(&pv)

}

func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {

	hash := crypto.Checksum(msg)

	pv := privKey.MakeFull()

	r, s, err := SignECDSA(&pv, hash, crypto.New)
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

func (pv PrivKey) MakeFull() PrivateKey {
	pvt := new(PrivateKey)
	pvt.PublicKey.Curve = weierstrass.Stark()
	pvt.D = big.NewInt(0).SetBytes(pv.Bytes())
	pvt.PublicKey.X, pvt.PublicKey.Y = pvt.PublicKey.Curve.ScalarBaseMult(pv.Bytes())
	return *pvt
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
	// pvt.PublicKey.Curve = c
	pvt.D = k
	// pvt.PublicKey.X, pvt.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	pv := PrivKey(pvt.D.Bytes())
	return &pv
}

/////////////////////////////////////////////////////////

type PubKey []byte //struct{ pb *PublicKey }

func (PubKey) TypeTag() string { return PubKeyName }

func (p PubKey) Type() string {
	return KeyType
}

type Address = bytes.HexBytes

func pubKeyFromPrivate(pv *PrivKey) PubKey {
	pvFull := pv.MakeFull()
	pb := (&(pvFull)).Public()
	return pb.MarshalCompressedStark()
}

func (p PubKey) Address() Address {
	if len(p) != PubKeySize {
		panic("pubkey is incorrect size")
	}
	return crypto.AddressHash(p)
}

func (p PubKey) IsNil() bool {
	if p == nil {
		return true
	}
	return false
}

func (p PubKey) Bytes() []byte {
	return []byte(p)
}

func (p PubKey) MakeFull() PublicKey {
	pb := UnmarshalCompressedStark(curve, []byte(p))
	return pb
}

func (p PubKey) VerifySignature(msg []byte, sig []byte) bool {

	hash := crypto.Checksum(msg)

	r, s, err := deserializeSig(sig)
	if err != nil {
		return false
	}
	pb := p.MakeFull()
	return Verify(&pb, hash, r, s)
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

func serializeSig(r *big.Int, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}

func deserializeSig(sig []byte) (r *big.Int, s *big.Int, err error) {
	if len(sig) != 64 {
		return nil, nil, errors.New("Invalid signature length")
	}

	chunked := utils.Split(sig, 32)

	rBytes := chunked[0]
	sBytes := chunked[1]

	r = new(big.Int).SetBytes(rBytes)
	s = new(big.Int).SetBytes(sBytes)
	return r, s, nil
}

//We modify MarshalCompressed so that we fit into 2*32 bytes.
func (p PublicKey) MarshalCompressedStark() PubKey {
	if p.IsNil() {
		panic("can't marshall nil key")
	}
	curve := p.Curve
	x := *p.X
	y := *p.Y

	byteLen := 2 * ((curve.Params().BitSize + 7) / 8)
	compressedX := make([]byte, byteLen/2)
	compressedY := make([]byte, byteLen/2)

	x.FillBytes(compressedX)
	y.FillBytes(compressedY)

	compressed := append(compressedX, compressedY...)

	return compressed
}

func UnmarshalCompressedStark(curve weierstrass.Curve, data []byte) PublicKey {

	byteLen := 2 * ((curve.Params().BitSize + 7) / 8)
	if len(data) != byteLen {
		// notest
		panic("marshalling failed, wrong byte len")

	}

	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:])

	if !curve.IsOnCurve(x, y) {
		return PublicKey{}
	}

	pb := PublicKey{curve, x, y}

	return pb
}
