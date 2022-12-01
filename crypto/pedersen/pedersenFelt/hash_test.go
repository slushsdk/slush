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
	hasher.Write(pedersen.ByteRounder(num1.Bytes()))
	hasher.Write(pedersen.ByteRounder(num2.Bytes()))

	var key snapshotKey
	copy(key[:], hasher.Sum(nil))

	fmt.Println(big.NewInt(0).SetBytes(key[:]))

}

func TestByteRounder(t *testing.T) {
	ba := []byte("asdv")
	n := big.NewInt(0).SetBytes(ba)
	m := big.NewInt(0).SetBytes(pedersen.ByteRounder(ba))

	require.Equal(t, n.Cmp(m), 0)
}
