package hashing

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen/felt"
	"github.com/tendermint/tendermint/crypto/utils"
)

// the expected values are generated in cairo, see cairo/test/test_hashing.cairo
func TestCairoHash2(t *testing.T) {

	// filename := "/Users/ago/projects/tendermint-stark/hash_test.json"
	filename := "../../../test_inputs/hash_test_array.json"

	data_out := utils.ImportJsonArray(filename)

	fmt.Printf("loaded json %s", data_out[0].Name)
	testCases := []utils.HashFeltTestCaseArray{
		0: {
			Name:     data_out[0].Name,
			Array:    data_out[0].Array,
			Expected: data_out[0].Expected,
		},
		1: {
			Name:     data_out[1].Name,
			Array:    data_out[1].Array,
			Expected: data_out[1].Expected,
		},
		2: {
			Name:     data_out[2].Name,
			Array:    data_out[2].Array,
			Expected: data_out[2].Expected,
		},
		3: {
			Name:     data_out[3].Name,
			Array:    data_out[3].Array,
			Expected: data_out[3].Expected,
		},
	}

	for i, tc := range testCases {
		felt1 := felt.New().SetBigInt(big.NewInt(tc.Array[0]))
		felt2 := felt.New().SetBigInt(big.NewInt(tc.Array[1]))
		result := hash2(felt1, felt2)
		require.Equal(t, tc.Expected, result.String(), "TestCAse%d %s failed: hashes don't match: %s != %s", i, tc.Name, tc.Expected, result.String())
	}
}

func TestCairoHashFelt(t *testing.T) {

	filename := "../../../test_inputs/hash_test_array.json"

	data_out := utils.ImportJsonArray(filename)
	testCases := []utils.HashFeltTestCaseArray{
		0: {
			Name:     data_out[4].Name,
			Array:    data_out[4].Array,
			Expected: data_out[4].Expected,
		},
	}

	for i, tc := range testCases {
		felt1 := felt.New().SetBigInt(big.NewInt(tc.Array[0]))
		result := hashFelt(felt1)
		require.Equal(t, tc.Expected, result.String(), "TestCase%d %s failed: hashes don't match: %s != %s", i, tc.Name, tc.Expected, result.String())
	}
}

func TestCairoHashFeltArray(t *testing.T) {

	filename := "../../../test_inputs/hash_test_array.json"

	data_out := utils.ImportJsonArray(filename)
	testCases := []utils.HashFeltTestCaseArray{
		0: {
			Name:     data_out[5].Name,
			Array:    data_out[5].Array,
			Expected: data_out[5].Expected,
		},
		1: {
			Name:     data_out[6].Name,
			Array:    data_out[6].Array,
			Expected: data_out[6].Expected,
		},
		2: {
			Name:     data_out[7].Name,
			Array:    data_out[7].Array,
			Expected: data_out[7].Expected,
		},
	}

	for i, tc := range testCases {
		feltArray := make([]*felt.Felt, len(tc.Array))
		for i := 0; i < len(tc.Array); i++ {
			feltArray[i] = felt.New().SetBigInt(big.NewInt(tc.Array[i]))
		}
		result := hashFeltArray(feltArray...)
		require.Equal(t, tc.Expected, result.String(), "TestCase%d %s failed: hashes don't match: %s != %s", i, tc.Name, tc.Expected, result.String())
	}
}

func TestCairoHash(t *testing.T) {
	filename := "../../../test_inputs/hash_test_array.json"

	data_out := utils.ImportJsonArray(filename)
	testCases := []utils.HashFeltTestCaseArray{
		0: {
			Name:     data_out[8].Name,
			Array:    data_out[8].Array,
			Expected: data_out[8].Expected,
		},
		1: {
			Name:     data_out[9].Name,
			Array:    data_out[9].Array,
			Expected: data_out[9].Expected,
		},
		2: {
			Name:     data_out[10].Name,
			Array:    data_out[10].Array,
			Expected: data_out[10].Expected,
		},
		3: {
			Name:     data_out[11].Name,
			Array:    data_out[11].Array,
			Expected: data_out[11].Expected,
		},
	}

	for i, tc := range testCases {
		feltArray := make([]*felt.Felt, len(tc.Array))
		for i := 0; i < len(tc.Array); i++ {
			feltArray[i] = felt.New().SetBigInt(big.NewInt(tc.Array[i]))
		}
		result := Hash(feltArray...)
		require.Equal(t, tc.Expected, result.String(), "TestCase%d %s failed: hashes don't match: %s != %s", i, tc.Name, tc.Expected, result.String())
	}
}
