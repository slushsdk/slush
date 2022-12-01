package pedersen_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/pedersen/pedersenFelt"
	"github.com/tendermint/tendermint/crypto/pedersen/pedersenInt128"
)

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestPedersenSimpleDigest(t *testing.T) {
	num1 := big.NewInt(44)
	num2 := big.NewInt(0)

	result := pedersen.Digest(num1, num2)

	isGreaterThanZero := result.Cmp(big.NewInt(0)) == 1
	require.True(t, isGreaterThanZero)
}

func TestPedersenArrayDigest(t *testing.T) {
	num := big.NewInt(44)

	result := pedersen.ArrayDigest(num, num, num, num)

	isGreaterThanZero := result.Cmp(big.NewInt(0)) == 1
	require.True(t, isGreaterThanZero)
}

// We got this result from the cairo playground pedersen hash function.
func TestDigest(t *testing.T) {
	num1 := big.NewInt(314)
	num2 := big.NewInt(159)
	expectedBigInt, _ := big.NewInt(0).SetString("307958720726328212653290369969069617958360335228383070119367204176047090109", 10)
	expected := expectedBigInt

	result := pedersen.Digest(num1, num2)

	require.Equal(t, result, expected)
}

func TestPedersenHash(t *testing.T) {
	hasher := pedersenInt128.New()
	data := []byte("ABC€")

	hasher.Write(data)
	result := hasher.Sum(nil)
	var resultFixedLen [32]byte
	copy(resultFixedLen[:], result)

	require.Equal(t, resultFixedLen, pedersenInt128.Sum256(data))

	resultInt := new(big.Int).SetBytes(result)
	expected, _ := new(big.Int).SetString("2760604002641969939589959074508015067181730793437535659828168196846743269396", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

// Also run in Cairo.
func TestPedersenIntArray(t *testing.T) {
	hasher := pedersenInt128.New()

	hasher.Write(pedersen.ByteRounder([]byte{101}))
	hasher.Write(pedersen.ByteRounder([]byte{102}))
	hasher.Write(pedersen.ByteRounder([]byte{103}))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)
	expected, _ := new(big.Int).SetString("1994640893838454634213538779823238090002580381689518562403970955531880917799", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

func TestPedersenIntArray2(t *testing.T) {
	hasher := pedersenInt128.New()

	hasher.Write(pedersen.ByteRounder(big.NewInt(116).Bytes()))
	hasher.Write(pedersen.ByteRounder(big.NewInt(7310314358442582377).Bytes()))
	hasher.Write(pedersen.ByteRounder(big.NewInt(7939082473277174873).Bytes()))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)

	hasher2 := pedersenInt128.New()
	hasher2.Write(append(make([]byte, 7), []byte("test-chain-IrF74Y")...))
	fmt.Println([]byte("test-chain-IrF74Y"))
	expected := big.NewInt(0).SetBytes(hasher2.Sum(nil))

	fmt.Println(expected)
	fmt.Println(resultInt)
	require.True(t, resultInt.Cmp(expected) == 0)
}

// Also run in Cairo.
func TestPedersenHashFeltArray(t *testing.T) {
	hasher := pedersenFelt.New()

	//we write the zeros for padding to simulate hashing a felt

	hasher.Write(append(make([]byte, 16), pedersen.ByteRounder(([]byte{104}))...))
	hasher.Write(append(make([]byte, 16), pedersen.ByteRounder(([]byte{105}))...))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)
	fmt.Println(resultInt)
	expected, _ := new(big.Int).SetString("949196962641716154526889172894504096264434458913100418940040777598300992821", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

func TestDoublePedersenHash(t *testing.T) {

	hasher := pedersenInt128.New()

	data := []byte("ABC€")

	hasher.Write(data)
	result := hasher.Sum(nil)

	secondHasher := pedersenInt128.New()
	secondHasher.Write(result)
	secondResult := secondHasher.Sum(nil)

	var secondResultFixedLen [32]byte
	copy(secondResultFixedLen[:], secondResult)

	intermediateRes1 := pedersenInt128.Sum256(data)

	var intermediateRes2 []byte
	intermediateRes2 = intermediateRes1[:]
	finalRes := pedersenInt128.Sum256(intermediateRes2)

	require.Equal(t, secondResultFixedLen, finalRes)

}
