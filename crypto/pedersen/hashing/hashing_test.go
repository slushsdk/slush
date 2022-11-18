package hashing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/pedersen/felt"
)

// the expected values are generated in cairo, see cairo/test/test_hashing.cairo
func TestHash2(t *testing.T) {
	type HashFeltTestCase struct {
		name     string
		num1     int64
		num2     int64
		expected string
	}
	testCases := []HashFeltTestCase{
		0: {
			name:     "",
			num1:     0,
			num2:     0,
			expected: "2089986280348253421170679821480865132823066470938446095505822317253594081284",
		},
		1: {
			name:     "",
			num1:     314,
			num2:     159,
			expected: "307958720726328212653290369969069617958360335228383070119367204176047090109",
		},
		2: {
			name:     "",
			num1:     987,
			num2:     654,
			expected: "2540319589456132300330493969278789717701149600812547910972637842370581449267",
		},
		3: {
			name:     "",
			num1:     123456789,
			num2:     987654321,
			expected: "3215027698461462532678621940423130825850775937567625383549699954271974824556",
		},
	}

	for i, tc := range testCases {
		felt1 := felt.New().SetBigInt(big.NewInt(tc.num1))
		felt2 := felt.New().SetBigInt(big.NewInt(tc.num2))
		result := hash2(felt1, felt2)
		require.Equal(t, tc.expected, result.String(), "TestCAse%d %s failed: hashes don't match: %s != %s", i, tc.name, tc.expected, result.String())
	}
}
func TestHashFelt(t *testing.T) {
	type HashFeltTestCase struct {
		name     string
		num      int64
		expected string
	}
	testCases := []HashFeltTestCase{
		0: {
			name:     "hash of zero should return the same as Hash2(0,0)",
			num:      0,
			expected: "2089986280348253421170679821480865132823066470938446095505822317253594081284",
		},
	}

	for i, tc := range testCases {
		felt1 := felt.New().SetBigInt(big.NewInt(tc.num))
		result := hashFelt(felt1)
		require.Equal(t, tc.expected, result.String(), "TestCase%d %s failed: hashes don't match: %s != %s", i, tc.name, tc.expected, result.String())
	}
}

func TestHashFeltArray(t *testing.T) {
	type HashFeltArrayTestCase struct {
		name     string
		numArray []int64
		expected string
	}
	testCases := []HashFeltArrayTestCase{
		0: {
			name:     "2 length array",
			numArray: []int64{104, 105},
			expected: "949196962641716154526889172894504096264434458913100418940040777598300992821",
		},
		1: {
			name:     "3 length array",
			numArray: []int64{44, 44, 44},
			expected: "18592255723457080959397934855987158832065438127005310151431763553740281190",
		},
		2: {
			name:     "10 length array",
			numArray: []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			expected: "554483969726199178082320267441426426111856244452951742913956080159496019129",
		},
	}

	for i, tc := range testCases {
		feltArray := make([]*felt.Felt, len(tc.numArray))
		for i := 0; i < len(tc.numArray); i++ {
			feltArray[i] = felt.New().SetBigInt(big.NewInt(tc.numArray[i]))
		}
		result := hashFeltArray(feltArray...)
		require.Equal(t, tc.expected, result.String(), "TestCase%d %s failed: hashes don't match: %s != %s", i, tc.name, tc.expected, result.String())
	}
}

func TestHash(t *testing.T) {
	type HashTestCase struct {
		name     string
		numArray []int64
		expected string
	}
	testCases := []HashTestCase{
		0: {
			name:     "empty result should return the same hash as HashFelt(0)",
			numArray: []int64{},
			expected: "2089986280348253421170679821480865132823066470938446095505822317253594081284",
		},
		1: {
			name:     "one length array should return the same hash as HashFelt",
			numArray: []int64{104},
			expected: "2147898189547448657228585229497353426722228748437533751634413599188914117252",
		},
		2: {
			name:     "longer array should return the same hash as HashFeltArray",
			numArray: []int64{104, 105},
			expected: "949196962641716154526889172894504096264434458913100418940040777598300992821",
		},
		3: {
			name:     "longer array should return the same hash as HashFeltArray",
			numArray: []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			expected: "554483969726199178082320267441426426111856244452951742913956080159496019129",
		},
	}

	for i, tc := range testCases {
		feltArray := make([]*felt.Felt, len(tc.numArray))
		for i := 0; i < len(tc.numArray); i++ {
			feltArray[i] = felt.New().SetBigInt(big.NewInt(tc.numArray[i]))
		}
		result := Hash(feltArray...)
		require.Equal(t, tc.expected, result.String(), "TestCase%d %s failed: hashes don't match: %s != %s", i, tc.name, tc.expected, result.String())
	}
}
