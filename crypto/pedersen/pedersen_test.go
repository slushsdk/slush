package pedersen_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestPedersen(t *testing.T) {
	result := pedersen.Digest(big.NewInt(44), big.NewInt(0))
	require.Equal(t, result.Cmp(big.NewInt(0)), 1)
}
