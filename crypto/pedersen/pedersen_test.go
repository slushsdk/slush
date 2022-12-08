package pedersen

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen/felt"
	"github.com/tendermint/tendermint/crypto/pedersen/hashing"
	"github.com/tendermint/tendermint/crypto/utils"
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
	felt1 := felt.New().SetBigInt(big.NewInt(29797))
	felt1Bytes := felt1.Bytes32()
	felts := []*felt.Felt{felt1}

	resFelts := getFeltsFromBytes(32)(felt1Bytes[:])
	require.IsType(t, []*felt.Felt{}, resFelts, "getFeltsFromBytes() should return a slice of felt.Felts")
	require.Equal(t, 1, len(resFelts), "getFeltsFromBytes should return a slice of felts with the length of 2")
	fmt.Println("resFelts", resFelts)
	for i, f := range resFelts {
		require.Equal(t, felts[i], f, "getFeltsFromBytes should return the correct felts")
	}
}

func TestCairoPedersenHashSum(t *testing.T) {
	// input := []byte("hello world")
	filename := "../../test_inputs/pedersen_test_array.json"

	data_out := utils.ImportJsonArray(filename)

	ph := New()
	ph.Write([]byte{byte(data_out[0].Array[0])})
	ph.Write([]byte{byte(data_out[0].Array[1])})
	ph.Write([]byte{byte(data_out[0].Array[2])})

	hash := ph.Sum(nil)
	expectedHash := data_out[0].Expected
	require.Equal(t, expectedHash[:], big.NewInt(0).SetBytes(hash[:]).String(), "Sum() should return the correct hash")

	ph128 := New128()
	ph128.Write([]byte{byte(data_out[0].Array[0])})
	ph128.Write([]byte{byte(data_out[0].Array[1])})
	ph128.Write([]byte{byte(data_out[0].Array[2])})
	hash128 := ph128.Sum(nil)
	expectedHash128 := data_out[0].Expected
	require.Equal(t, expectedHash128[:], big.NewInt(0).SetBytes(hash128[:]).String(), "Sum() should return the correct hash")
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

func TestCairoSum(t *testing.T) {
	filename := "../../test_inputs/pedersen_test_array.json"

	data_out := utils.ImportJsonArray(filename)

	// this is the same piece of code as in pedersen/Sum128
	var ph pedersenHash
	ph.Reset()
	ph.Write([]byte{byte(data_out[0].Array[0])})
	ph.Write([]byte{byte(data_out[0].Array[1])})
	ph.Write([]byte{byte(data_out[0].Array[2])})
	expected := data_out[0].Expected

	hash := ph.checkSum()
	require.Equal(t, 32, len(hash), "Sum128() should return a 32 byte slice")
	require.Equal(t, big.NewInt(0).SetBytes(hash[:]).String(), expected, " railed: hashes don't match: %s != %s", hash, 42)

	// input := []byte("hello world")
	// hash := Sum(input)
	// require.Equal(t, 32, len(hash), "Sum() should return a 32 byte slice")
	// expectedHash := hashing.Hash(getFeltsFromBytes(32)(input)...).Bytes32()
	// require.Equal(t, expectedHash, hash, "Sum() should return the same hash as hashing.Hash()")
}

func TestCairoSum128(t *testing.T) {
	filename := "../../test_inputs/pedersen_test_array.json"

	data_out := utils.ImportJsonArray(filename)

	// this is the same piece of code as in pedersen/Sum128
	var ph pedersenHash
	ph.Reset()
	ph.is128 = true
	ph.Write([]byte{byte(data_out[0].Array[0])})
	ph.Write([]byte{byte(data_out[0].Array[1])})
	ph.Write([]byte{byte(data_out[0].Array[2])})
	expected := data_out[0].Expected

	hash := ph.checkSum()
	require.Equal(t, 32, len(hash), "Sum128() should return a 32 byte slice")
	require.Equal(t, big.NewInt(0).SetBytes(hash[:]).String(), expected, " railed: hashes don't match: %s != %s", hash, 42)
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
