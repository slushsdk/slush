package abstractions_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	ihash "github.com/tendermint/tendermint/crypto/abstractions"
)

type snapshotKey [ihash.Size]byte

// the purpose of this test is primarily to ensure that the randomness
// generation won't error.
func TestHasher(t *testing.T) {
	hasher := ihash.New()
	hasher.Write([]byte(fmt.Sprintf("%v:%v:%v", 10, 10, 10)))
	hasher.Write([]byte(fmt.Sprintf("%v:%v:%v", 10, 50, 10)))

	var key snapshotKey
	copy(key[:], hasher.Sum(nil))

	fmt.Println(hasher.Sum(nil))

	fmt.Println(key)
}

func TestByteRounder(t *testing.T) {
	ba := []byte("asdv")
	n := big.NewInt(0).SetBytes(ba)
	m := big.NewInt(0).SetBytes(ihash.ByteRounder(ba))

	require.Equal(t, n.Cmp(m), 0)
}