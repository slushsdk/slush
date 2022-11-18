package pedersen

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen/felt"
	"github.com/tendermint/tendermint/crypto/pedersen/hashing"
)

func TestNew(t *testing.T) {
	ph := New()
	require.IsType(t, &pedersenHash{}, ph, "New() should return a pedersenHash")

	st := reflect.TypeOf(ph)
	_, ok := st.MethodByName("Size")
	require.True(t, ok, "pedersenHash should have a method named Size")
	_, ok = st.MethodByName("BlockSize")
	require.True(t, ok, "pedersenHash should have a method named BlockSize")
	_, ok = st.MethodByName("Reset")
	require.True(t, ok, "pedersenHash should have a method named Reset")
	_, ok = st.MethodByName("Write")
	require.True(t, ok, "pedersenHash should have a method named Write")
	_, ok = st.MethodByName("Sum")
	require.True(t, ok, "pedersenHash should have a method named Sum")

	require.Equal(t, 32, ph.Size(), "Size() should return 32")
	require.Equal(t, 32, ph.BlockSize(), "BlockSize() should return 32")
}

func TestNew128(t *testing.T) {
	ph := New128()
	require.IsType(t, &pedersenHash{}, ph, "New128() should return a pedersenHash")

	st := reflect.TypeOf(ph)
	_, ok := st.MethodByName("Size")
	require.True(t, ok, "pedersenHash should have a method named Size")
	_, ok = st.MethodByName("BlockSize")
	require.True(t, ok, "pedersenHash should have a method named BlockSize")
	_, ok = st.MethodByName("Reset")
	require.True(t, ok, "pedersenHash should have a method named Reset")
	_, ok = st.MethodByName("Write")
	require.True(t, ok, "pedersenHash should have a method named Write")
	_, ok = st.MethodByName("Sum")
	require.True(t, ok, "pedersenHash should have a method named Sum")

	require.Equal(t, 32, ph.Size(), "Size() should return 32")
	require.Equal(t, 16, ph.BlockSize(), "BlockSize() should return 16")
}

func TestSize(t *testing.T) {
	ph := New()
	require.Equal(t, 32, ph.Size(), "Size() should return 32")
}

func TestBlockSize(t *testing.T) {
	ph := New()
	require.Equal(t, 32, ph.BlockSize(), "BlockSize() should return 32")

	ph = New128()
	require.Equal(t, 16, ph.BlockSize(), "BlockSize() should return 16")
}

func TestGetFeltsFromBytes(t *testing.T) {
	felt1 := felt.New().SetBigInt(big.NewInt(24389))
	felt1Bytes := felt1.Bytes32()
	felt2 := felt.New().SetBigInt(big.NewInt(3453452))
	felt2Bytes := felt2.Bytes32()
	felts := []*felt.Felt{felt1, felt2}
	inputBytes := append(felt1Bytes[:], felt2Bytes[:]...)

	resFelts := getFeltsFromBytes(32)(inputBytes)
	require.IsType(t, []*felt.Felt{}, resFelts, "getFeltsFromBytes() should return a slice of felt.Felts")
	require.Equal(t, 2, len(resFelts), "getFeltsFromBytes should return a slice of felts with the length of 2")
	for i, f := range resFelts {
		require.Equal(t, felts[i], f, "getFeltsFromBytes should return the correct felts")
	}
}

func TestPedersenHashSum(t *testing.T) {
	input := []byte("hello world")
	ph := New()
	ph.Write(input)
	hash := ph.Sum(nil)
	expectedHash := hashing.Hash(getFeltsFromBytes(32)(input)...).Bytes32()
	require.Equal(t, expectedHash[:], hash, "Sum() should return the correct hash")

	ph128 := New128()
	ph128.Write(input)
	hash128 := ph128.Sum(nil)
	expectedHash128 := hashing.Hash(getFeltsFromBytes(16)(input)...).Bytes32()
	require.Equal(t, expectedHash128[:], hash128, "Sum() should return the correct hash")
}

func TestWrite(t *testing.T) {
	input := []byte("hello world")
	ph := New()
	hashBeforeWrite := ph.Sum(nil)
	ph.Write(input)
	hashAfterWrite := ph.Sum(nil)
	require.NotEqual(t, hashBeforeWrite, hashAfterWrite, "Sum() should return a different hash after Write()")
	expectedHash := hashing.Hash(getFeltsFromBytes(32)(input)...).Bytes32()
	require.Equal(t, expectedHash[:], hashAfterWrite, "The hash after write should be the same as the result of hashing.Hash()")
}

func TestSum(t *testing.T) {
	input := []byte("hello world")
	hash := Sum(input)
	require.Equal(t, 32, len(hash), "Sum() should return a 32 byte slice")
	expectedHash := hashing.Hash(getFeltsFromBytes(32)(input)...).Bytes32()
	require.Equal(t, expectedHash, hash, "Sum() should return the same hash as hashing.Hash()")
}

func TestSum128(t *testing.T) {
	input := []byte("hello world")
	hash := Sum128(input)
	require.Equal(t, 32, len(hash), "Sum128() should return a 32 byte slice")
	expectedHash := hashing.Hash(getFeltsFromBytes(16)(input)...).Bytes32()
	require.Equal(t, expectedHash, hash, "Sum128() should return the same hash as hashing.Hash()")
}

func TestReset(t *testing.T) {
	input := []byte("hello world")
	ph := New()
	hashBeforeWrite := ph.Sum(nil)
	ph.Write(input)
	hashAfterWrite := ph.Sum(nil)
	require.NotEqual(t, hashBeforeWrite, hashAfterWrite, "Sum() should return a different hash after Write()")
	ph.Reset()
	hashAfterReset := ph.Sum(nil)
	require.Equal(t, hashBeforeWrite, hashAfterReset, "Sum() should return the same hash after Reset() as before Write()")
}
