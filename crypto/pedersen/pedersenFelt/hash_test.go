package pedersenFelt_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/pedersen/pedersenFelt"
)

type snapshotKey [pedersenFelt.Size]byte

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestHasher(t *testing.T) {
	hasher := pedersenFelt.New()

	num1, _ := big.NewInt(0).SetString("104", 10)
	num2, _ := big.NewInt(0).SetString("105", 10)
	hasher.Write(pedersen.ByteRounderInt128(num1.Bytes()))
	hasher.Write(pedersen.ByteRounderInt128(num2.Bytes()))

	var key snapshotKey
	copy(key[:], hasher.Sum(nil))

	fmt.Println(big.NewInt(0).SetBytes(key[:]))

}

// Also run in Cairo.
func TestPedersenHashFeltArray(t *testing.T) {
	hasher := pedersenFelt.New()

	//we write the zeros for padding to simulate hashing a felt

	hasher.Write(append(make([]byte, 16), pedersen.ByteRounderInt128(([]byte{104}))...))
	hasher.Write(append(make([]byte, 16), pedersen.ByteRounderInt128(([]byte{105}))...))

	result := hasher.Sum(nil)

	resultInt := new(big.Int).SetBytes(result)
	fmt.Println(resultInt)
	expected, _ := new(big.Int).SetString("949196962641716154526889172894504096264434458913100418940040777598300992821", 10)
	require.True(t, resultInt.Cmp(expected) == 0)
}
