package pedersen_test

import (
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
	data := []byte("ABC€")

	hasher.Write(data)
	result := hasher.Sum(nil)
	var resultFixedLen [32]byte
	copy(resultFixedLen[:], result)

	require.Equal(t, resultFixedLen, pedersen.Sum256(data))

	resultInt := new(big.Int).SetBytes(result)
	expected, _ := new(big.Int).SetString("2242061308241901177902337403014839264202837952334584323802454450099490424417", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

func TestDoublePedersenHash(t *testing.T) {

	hasher := pedersen.New()

	data := []byte("ABC€")

	hasher.Write(data)
	result := hasher.Sum(nil)

	secondHasher := pedersen.New()
	secondHasher.Write(result)
	secondResult := secondHasher.Sum(nil)

	var secondResultFixedLen [32]byte
	copy(secondResultFixedLen[:], secondResult)

	intermediateRes1 := pedersen.Sum256(data)

	var intermediateRes2 []byte
	intermediateRes2 = intermediateRes1[:]
	finalRes := pedersen.Sum256(intermediateRes2)

	require.Equal(t, secondResultFixedLen, finalRes)

}
