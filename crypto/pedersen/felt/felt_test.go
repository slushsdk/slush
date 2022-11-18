package felt

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	tmrand "github.com/tendermint/tendermint/libs/rand"
)

func TestNew(t *testing.T) {
	actualFelt1 := new(Felt)
	actualFelt2 := New()
	expected := new(big.Int)

	feltIntInBigInt1 := (*big.Int)(actualFelt1)
	cmpRes := expected.Cmp(feltIntInBigInt1) // 0 if equal
	require.Equal(t, 0, cmpRes, "TestCase0 failed: expected %v, got %v", expected, feltIntInBigInt1)

	feltIntInBigInt2 := (*big.Int)(actualFelt2)
	cmpRes2 := expected.Cmp(feltIntInBigInt1) // 0 if equal
	require.Equal(t, 0, cmpRes2, "TestCase1 failed: expected %v, got %v", expected, feltIntInBigInt2)
}

func TestString(t *testing.T) {
	feltInt := new(Felt)
	bigInt := new(big.Int)

	feltString := feltInt.String()
	bigIntString := bigInt.String()

	require.Equal(t, bigIntString, feltString, "TestCase0 failed: expected %s, got %s", bigIntString, feltString)
}

func TestSetBytes(t *testing.T) {
	type SetBytesTestCase struct {
		name     string
		input    []byte
		expected *big.Int
	}
	testCases := []SetBytesTestCase{
		0: {
			name:     "SetBytes: 0",
			input:    []byte{0},
			expected: big.NewInt(0),
		},
		1: {
			name:     "SetBytes: 1",
			input:    []byte{1},
			expected: big.NewInt(1),
		},
		2: {
			name:     "SetBytes: 2",
			input:    []byte{2},
			expected: big.NewInt(2),
		},
	}
	for i, tc := range testCases {
		result := New().SetBytes(tc.input)
		resultBigInt := (*big.Int)(result)
		require.Equal(t, tc.expected.String(), resultBigInt.String(), "TestCase%d %s failed: %s != %s", i, tc.name, tc.expected.String(), result.String())
	}
}

func TestSetBigInt(t *testing.T) {
	type SetBigIntTestCase struct {
		name     string
		input    *big.Int
		expected *big.Int
	}
	testCases := []SetBigIntTestCase{
		0: {
			name:     "SetBigInt: 0",
			input:    big.NewInt(0),
			expected: big.NewInt(0),
		},
		1: {
			name:     "SetBigInt: 1",
			input:    big.NewInt(1),
			expected: big.NewInt(1),
		},
		2: {
			name:     "SetBigInt: 2",
			input:    big.NewInt(2),
			expected: big.NewInt(2),
		},
	}
	for i, tc := range testCases {
		result := New().SetBigInt(tc.input)
		resultBigInt := (*big.Int)(result)
		require.Equal(t, tc.expected.String(), resultBigInt.String(), "TestCase%d %s failed: %s != %s", i, tc.name, tc.expected.String(), result.String())
	}
}

func TestCheckFeltRange(t *testing.T) {
	// testing with bottomLimit - 1 = 0 - 1
	// err expected
	negative := big.NewInt(-1)
	err := checkFeltRange(negative)
	require.Error(t, err, "TestCase0: out of range check (bottom) failed, expected error, got %v", err)

	// testing with topLimit + 1 = 3618502788666131213697322783095070105623107215331596699973092056135872020480 + 1
	// error expected
	tooLarge, _ := new(big.Int).SetString("800000000000011000000000000000000000000000000000000000000000001", 16)
	err2 := checkFeltRange(tooLarge)
	require.Error(t, err2, "TestCase1: out of range check (top) failed, expected error, got %v", err2)

	// testing with bottomLimit = 0
	// no error expected
	bottomLimit := big.NewInt(0)
	err3 := checkFeltRange(bottomLimit)
	require.NoError(t, err3, "TestCase2: bottom limit check failed, expected no error, got %v", err3)

	// testing with topLimit = 3618502788666131213697322783095070105623107215331596699973092056135872020480
	// no error expected
	topLimit, _ := new(big.Int).SetString("800000000000011000000000000000000000000000000000000000000000000", 16)
	err4 := checkFeltRange(topLimit)
	require.NoError(t, err4, "TestCase3: top limit check failed, expected no error, got %v", err4)

	// testing with a random number in the range
	// no error expected
	randomNumber := new(big.Int).SetBytes(tmrand.FeltBytes(32))
	err5 := checkFeltRange(randomNumber)
	require.NoError(t, err5, "TestCase4: in range check failed, expected no error, got %v", err5)
}

func TestTransformLength(t *testing.T) {
	type TransformLengthTestCase struct {
		name     string
		input    []byte
		expected [32]byte
	}
	testCases := []TransformLengthTestCase{
		0: {
			name:     "simple rounding 1",
			input:    []byte{0},
			expected: *(*[32]byte)(make([]byte, 32)),
		},
		1: {
			name:     "simple rounding 2",
			input:    []byte{1},
			expected: *(*[32]byte)(append(make([]byte, 31), []byte{1}...)),
		},
		2: {
			name:     "simple rounding 3",
			input:    []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			expected: *(*[32]byte)(append(make([]byte, 16), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}...)),
		},
		3: {
			name:     "if size is 32 do not transform",
			input:    []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
			expected: *(*[32]byte)([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}),
		},
	}
	for i, tc := range testCases {
		result := transformLength(tc.input)
		require.Equal(t, tc.expected, result, "TestCase%d %s failed: %v != %v", i, tc.name, tc.expected, result)
	}
}

func TestBytes32(t *testing.T) {
	type BytesTestCase struct {
		name     string
		input    *big.Int
		expected [32]byte
	}
	testCases := []BytesTestCase{
		0: {
			name:     "Bytes: 0",
			input:    big.NewInt(0),
			expected: transformLength(big.NewInt(0).Bytes()),
		},
		1: {
			name:     "Bytes: 1",
			input:    big.NewInt(1),
			expected: transformLength(big.NewInt(1).Bytes()),
		},
		2: {
			name:     "Bytes: 2",
			input:    big.NewInt(2),
			expected: transformLength(big.NewInt(2).Bytes()),
		},
	}
	for i, tc := range testCases {
		result := New().SetBigInt(tc.input).Bytes32()
		require.Equal(t, tc.expected, result, "TestCase%d %s failed: %v != %v", i, tc.name, tc.expected, result)
	}
}
