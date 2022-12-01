package pedersen_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen"
)

func TestByteRounderFelt(t *testing.T) {
	type TestCaseByteRounderFelt struct {
		name     string
		input    []byte
		expected []byte
	}

	testCases := []TestCaseByteRounderFelt{
		{
			name:     "TestCase1, simple rounding to 32 bytes",
			input:    []byte{97, 115, 100, 118},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		{
			name:     "TestCase2, if the input is already 32 bytes, it should not change",
			input:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		{
			name:     "TestCase3, if the input is more than 16 bytes, it should round it to the upper 16 bytes",
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	for _, tc := range testCases {
		result := pedersen.ByteRounderFelt(tc.input)
		require.Equal(t, tc.expected, result, "%s failed", tc.name)
	}
}

func TestPedersenHashFelt(t *testing.T) {
	type TestCasePedersenHashFelt struct {
		name     string
		input    [32]byte
		expected [32]byte
	}

	testCases := []TestCasePedersenHashFelt{
		{
			name:     "TestCase1, hashing 0",
			input:    [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},                                             // 0
			expected: [32]byte{4, 158, 227, 235, 168, 193, 96, 7, 0, 238, 27, 135, 235, 89, 159, 22, 113, 107, 11, 16, 34, 148, 119, 51, 85, 31, 222, 64, 80, 202, 104, 4}, // 2089986280348253421170679821480865132823066470938446095505822317253594081284
		},
	}

	for _, tc := range testCases {
		result := pedersen.PedersenHashFelt(tc.input)
		require.Equal(t, tc.expected, result, "%s failed: hashes don't match", tc.name)
	}
}

func TestPedersenHashFeltArray(t *testing.T) {
	type TestCasePedersenHashFeltArray struct {
		name     string
		input    []string
		expected string
	}

	testCases := []TestCasePedersenHashFeltArray{
		{
			name:     "TestCase1",
			input:    []string{"104", "105"},
			expected: "949196962641716154526889172894504096264434458913100418940040777598300992821",
		},
	}
	for _, tc := range testCases {
		var inputArray []byte
		for _, input := range tc.input {
			bigInteger, _ := big.NewInt(0).SetString(input, 10)
			rounded := pedersen.ByteRounderFelt(bigInteger.Bytes())
			inputArray = append(inputArray, rounded...)
		}

		result := pedersen.PedersenHashFeltArray(inputArray)
		resultInt := new(big.Int).SetBytes(result[:])
		require.Equal(t, tc.expected, resultInt.String(), "%s failed: hashes don't match", tc.name)
	}
}
