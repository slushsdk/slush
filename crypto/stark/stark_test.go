package stark_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/stark"
	"github.com/tendermint/tendermint/crypto/weierstrass"
)

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
