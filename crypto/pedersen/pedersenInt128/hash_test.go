package pedersenInt128_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen"

	"github.com/tendermint/tendermint/crypto/pedersen/pedersenInt128"
)

type snapshotKey [pedersenInt128.Size]byte

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestHasher(t *testing.T) {
	hasher := pedersenInt128.New()
	num1, _ := big.NewInt(0).SetString("101", 10)
	num2, _ := big.NewInt(0).SetString("102", 10)
	num3, _ := big.NewInt(0).SetString("103", 10)
	hasher.Write(pedersen.ByteRounderInt128(num1.Bytes()))
	hasher.Write(pedersen.ByteRounderInt128(num2.Bytes()))
	hasher.Write(pedersen.ByteRounderInt128(num3.Bytes()))

	var key snapshotKey
	copy(key[:], hasher.Sum(nil))

	fmt.Println(big.NewInt(0).SetBytes(key[:]))
}

func TestPedersenHash(t *testing.T) {
	hasher := pedersenInt128.New()
	data := []byte("ABC€") // [65 66 67 226 130 172] = 71752862565036

	hasher.Write(data)
	result := hasher.Sum(nil)
	var resultFixedLen [32]byte
	copy(resultFixedLen[:], result)

	require.Equal(t, resultFixedLen, pedersenInt128.Sum256(data))

	resultInt := big.NewInt(0).SetBytes(result)
	expected := "2242061308241901177902337403014839264202837952334584323802454450099490424417"
	require.Equal(t, expected, resultInt.String())
}

func TestPedersenIntArray(t *testing.T) {
	hasher := pedersenInt128.New()

	hasher.Write(pedersen.ByteRounderInt128([]byte{101}))
	hasher.Write(pedersen.ByteRounderInt128([]byte{102}))
	hasher.Write(pedersen.ByteRounderInt128([]byte{103}))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)
	expected, _ := new(big.Int).SetString("1994640893838454634213538779823238090002580381689518562403970955531880917799", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}

func TestPedersenIntArray2(t *testing.T) {
	hasher := pedersenInt128.New()

	chunk1 := big.NewInt(116)
	chunk2, _ := big.NewInt(0).SetString("134851498068554549348179021563090646105", 10)

	hasher.Write(pedersen.ByteRounderInt128(chunk1.Bytes()))
	hasher.Write(pedersen.ByteRounderInt128(chunk2.Bytes()))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)

	hasher2 := pedersenInt128.New()
	hasher2.Write(pedersen.ByteRounderInt128([]byte("test-chain-IrF74Y")))
	fmt.Println([]byte("test-chain-IrF74Y"))
	expected := big.NewInt(0).SetBytes(hasher2.Sum(nil))

	fmt.Println(expected)
	fmt.Println(resultInt)
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

	intermediateRes2 := intermediateRes1[:]
	finalRes := pedersenInt128.Sum256(intermediateRes2)

	require.Equal(t, secondResultFixedLen, finalRes)

}
