package stark_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen/felt"
	"github.com/tendermint/tendermint/crypto/pedersen/hashing"
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

// imported signature from https://www.cairo-lang.org/docs/hello_starknet/signature_verification.html?highlight=signature#interacting-with-the-contract
// to make sure of compatibility
func TestImportedSig(t *testing.T) {

	//we have to use this specially to match the raw starknet hashing.
	hashint := hashing.Hash(felt.New().SetBigInt(big.NewInt(4321))).Bytes32()
	hash := hashint[:]

	//we have to recreate the full public key (with y coordinate) from the imported pubkey.
	pubx, _ := big.NewInt(0).SetString("1628448741648245036800002906075225705100596136133912895015035902954123957052", 10)
	pubmarshalled := append([]byte{0x3}, pubx.Bytes()...)
	pubx, puby := weierstrass.UnmarshalCompressed(weierstrass.Stark(), pubmarshalled)
	publicKey := stark.PublicKey{weierstrass.Stark(), pubx, puby}

	sigr, _ := big.NewInt(0).SetString("1225578735933442828068102633747590437426782890965066746429241472187377583468", 10)
	sigs, _ := big.NewInt(0).SetString("3568809569741913715045370357918125425757114920266578211811626257903121825123", 10)

	//we have to mod out by N.
	sigrSmall := big.NewInt(0)
	sigsSmall := big.NewInt(0)

	sigrSmall.Mod(sigr, weierstrass.Stark().Params().N)
	sigsSmall.Mod(sigs, weierstrass.Stark().Params().N)

	res := stark.Verify(&publicKey, hash, sigrSmall, sigsSmall)

	require.True(t, res)

}
