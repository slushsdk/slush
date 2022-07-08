package stark_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/stark"
)

func TestGenPrivKey(t *testing.T) {
	pv := stark.GenPrivKey()
	require.Equal(t, len(pv.Bytes()), 32)
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
	require.Equal(t, len(pb.Bytes()), 32)
}

func TestSignAndVerify(t *testing.T) {
	pv := stark.GenPrivKey()
	pb := pv.PubKey()

	msg := []byte("hello world")
	sig, _ := pv.Sign(msg)

	pb.VerifySignature(msg, sig)
}
