package pedersen_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen"
)

func TestDigest(t *testing.T) {
	type TestCaseDigest struct {
		name     string
		num1     *big.Int
		num2     *big.Int
		expected string
	}
	testCases := []TestCaseDigest{
		{
			name:     "TestCase 1",
			num1:     big.NewInt(0),
			num2:     big.NewInt(0),
			expected: "2089986280348253421170679821480865132823066470938446095505822317253594081284",
		},
		{
			name:     "TestCase 2",
			num1:     big.NewInt(314),
			num2:     big.NewInt(159),
			expected: "307958720726328212653290369969069617958360335228383070119367204176047090109",
		},
		{
			name:     "TestCase 3",
			num1:     big.NewInt(987),
			num2:     big.NewInt(654),
			expected: "2540319589456132300330493969278789717701149600812547910972637842370581449267",
		},
		{
			name:     "TestCase 4",
			num1:     big.NewInt(123456789),
			num2:     big.NewInt(987654321),
			expected: "3215027698461462532678621940423130825850775937567625383549699954271974824556",
		},
	}

	for _, tc := range testCases {
		result := pedersen.Digest(tc.num1, tc.num2)
		require.Equal(t, tc.expected, result.String(), "%s failed: hashes don't match: %s != %s", tc.name, tc.expected, result.String())
	}
}

func TestArrayDigest(t *testing.T) {
	type TestCaseDigest struct {
		name     string
		numArray []*big.Int
		expected string
	}
	testCases := []TestCaseDigest{
		{
			name:     "TestCase 1",
			numArray: []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9)},
			expected: "554483969726199178082320267441426426111856244452951742913956080159496019129",
		},
		{
			name:     "TestCase 2",
			numArray: []*big.Int{big.NewInt(44), big.NewInt(44), big.NewInt(44)},
			expected: "18592255723457080959397934855987158832065438127005310151431763553740281190",
		},
	}

	for _, tc := range testCases {
		result := pedersen.ArrayDigest(tc.numArray...)
		require.Equal(t, tc.expected, result.String(), "%s failed: hashes don't match: %s != %s", tc.name, tc.expected, result.String())
	}
}
