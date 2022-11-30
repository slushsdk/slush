package pedersen_test

import (
	"fmt"
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

// We got this result from the cairo playground pedersen hash function.
func TestDigest(t *testing.T) {
	expected, _ := big.NewInt(0).SetString("307958720726328212653290369969069617958360335228383070119367204176047090109", 10)
	result := pedersen.Digest(big.NewInt(314), big.NewInt(159))
	require.Equal(t, result.Cmp(expected), 0)

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
	expected, _ := new(big.Int).SetString("2760604002641969939589959074508015067181730793437535659828168196846743269396", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

//Also run in Cairo.
func TestPedersenIntArray(t *testing.T) {
	hasher := pedersen.New()

	hasher.Write(pedersen.ByteRounder([]byte{101}))
	hasher.Write(pedersen.ByteRounder([]byte{102}))
	hasher.Write(pedersen.ByteRounder([]byte{103}))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)
	expected, _ := new(big.Int).SetString("1994640893838454634213538779823238090002580381689518562403970955531880917799", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

func TestPedersenIntArray2(t *testing.T) {
	hasher := pedersen.New()

	hasher.Write(pedersen.ByteRounder(big.NewInt(8387236823862306913).Bytes()))
	hasher.Write(pedersen.ByteRounder(big.NewInt(7597059414893672244).Bytes()))
	hasher.Write(pedersen.ByteRounder(big.NewInt(89).Bytes()))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)

	hasher2 := pedersen.New()
	hasher2.Write(append(make([]byte, 7), []byte("test-chain-IrF74Y")...))
	fmt.Println([]byte("test-chain-IrF74Y"))
	expected := big.NewInt(0).SetBytes(hasher2.Sum(nil))

	fmt.Println(expected)
	fmt.Println(resultInt)
	require.True(t, resultInt.Cmp(expected) == 0)
}

//Also run in Cairo.
func TestPedersenHashFeltArray(t *testing.T) {
	hasher := pedersen.New()

	//we write the zeros for padding to simulate hashing a felt

	hasher.Write(append(make([]byte, 24), pedersen.ByteRounder(([]byte{104}))...))
	hasher.Write(append(make([]byte, 24), pedersen.ByteRounder(([]byte{105}))...))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)
	fmt.Println(resultInt)
	expected, _ := new(big.Int).SetString("2646498606925522204838679506445363388192401594606070690927100495992848444995", 10)
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
