package pedersen_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen"
)

func TestByteRounderInt128(t *testing.T) {
	type TestCaseByteRounderInt128 struct {
		name     string
		input    []byte
		expected []byte
	}

	testCases := []TestCaseByteRounderInt128{
		{
			name:     "TestCase1, simple rounding to 16 bytes",
			input:    []byte{97, 115, 100, 118},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		{
			name:     "TestCase2, if the input is already 16 bytes, it should not change",
			input:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		{
			name:     "TestCase3, if the input is more than 16 bytes, it should round it to the upper 16 bytes",
			input:    []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expected: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	for _, tc := range testCases {
		result := pedersen.ByteRounderInt128(tc.input)
		require.Equal(t, tc.expected, result, "%s failed: hashes don't match", tc.name)
	}
}

func TestPedersenHashInt128(t *testing.T) {
	type TestCasePedersenHashInt128 struct {
		name     string
		input    [16]byte
		expected [32]byte
	}

	testCases := []TestCasePedersenHashInt128{
		{
			name:     "TestCase1, hashing 0",
			input:    [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},                                                                                             // 0
			expected: [32]byte{4, 158, 227, 235, 168, 193, 96, 7, 0, 238, 27, 135, 235, 89, 159, 22, 113, 107, 11, 16, 34, 148, 119, 51, 85, 31, 222, 64, 80, 202, 104, 4}, // 2089986280348253421170679821480865132823066470938446095505822317253594081284
		},
	}

	for _, tc := range testCases {
		result := pedersen.PedersenHashInt128(tc.input)
		require.Equal(t, tc.expected, result, "%s failed: hashes don't match", tc.name)
	}
}

func TestPedersenHashInt128Array(t *testing.T) {
	type TestCasePedersenHashInt128Array struct {
		name     string
		input    []string
		expected string
	}

	testCases := []TestCasePedersenHashInt128Array{
		{
			name:     "TestCase1",
			input:    []string{"101", "102", "103"},
			expected: "1994640893838454634213538779823238090002580381689518562403970955531880917799",
		},
		{
			name:     "TestCase2",
			input:    []string{"116", "134851498068554549348179021563090646105"},
			expected: "3568506871802686777317263434961222752130400696969231757318398670757708504165",
		},
	}
	for _, tc := range testCases {
		var inputArray []byte
		for _, input := range tc.input {
			bigInteger, _ := big.NewInt(0).SetString(input, 10)
			rounded := pedersen.ByteRounderInt128(bigInteger.Bytes())
			inputArray = append(inputArray, rounded...)
		}

		result := pedersen.PedersenHashInt128Array(inputArray)
		resultInt := new(big.Int).SetBytes(result[:])
		require.Equal(t, tc.expected, resultInt.String(), "%s failed: hashes don't match", tc.name)
	}
}
