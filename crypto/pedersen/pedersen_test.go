package pedersen_test

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestPedersenSimpleDigest(t *testing.T) {
	result := pedersen.Digest(big.NewInt(44), big.NewInt(0))
	require.Equal(t, result.Cmp(big.NewInt(0)), 1)
}

func TestPedersenArrayDigest(t *testing.T) {
	result := pedersen.ArrayDigest(big.NewInt(44), big.NewInt(44), big.NewInt(44), big.NewInt(44))
	require.Equal(t, result.Cmp(big.NewInt(0)), 1)
}

func TestPedersenHash(t *testing.T) {
	hasher := pedersen.New()
	hasher.Write([]byte{10, 10, 10})
	result := hasher.Sum(nil)
	resultInt := binary.BigEndian.Uint64(result)
	require.Greater(t, resultInt, uint64(0))
}
