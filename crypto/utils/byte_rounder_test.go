package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestByteRounder(t *testing.T) {
	type TestCaseByteRounder struct {
		name         string
		roundingSize int
		input        []byte
		expected     []byte
	}

	testCases := []TestCaseByteRounder{
		0: {
			name:         "simple rounding to 16 bytes",
			roundingSize: 16,
			input:        []byte{97, 115, 100, 118},
			expected:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		1: {
			name:         "if the input is already 16 bytes, it should not change",
			roundingSize: 16,
			input:        []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
			expected:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		2: {
			name:         "if the input is more than 16 bytes, it should round it to the upper 16 bytes",
			roundingSize: 16,
			input:        []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expected:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
		3: {
			name:         "simple rounding to 32 bytes",
			roundingSize: 32,
			input:        []byte{97, 115, 100, 118},
			expected:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		4: {
			name:         "if the input is already 32 bytes, it should not change",
			roundingSize: 32,
			input:        []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
			expected:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 115, 100, 118},
		},
		5: {
			name:         "if the input is more than 32 bytes, it should round it to the upper 32 bytes",
			roundingSize: 32,
			input:        []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expected:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
	}

	for _, tc := range testCases {
		result := ByteRounder(tc.roundingSize)(tc.input)
		require.Equal(t, tc.expected, result, "%s failed", tc.name)
	}
}
