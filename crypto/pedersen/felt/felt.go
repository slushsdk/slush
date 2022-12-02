package felt

import (
	"fmt"
	"math/big"
)

const size = 32

type Felt big.Int

// The inclusive bottom and th exclusive top limits of the felt range (0 <= x <= 2²⁵¹ + 17·2¹⁹²)
// bottom = 0,
// top = 3618502788666131213697322783095070105623107215331596699973092056135872020480
var (
	bottomLimit = big.NewInt(0)
	topLimit, _ = new(big.Int).SetString("800000000000011000000000000000000000000000000000000000000000000", 16)
)

// New returns a new Felt
func New() *Felt {
	return new(Felt)
}

// SetBytes sets a Felt's value from a byte slice, if the input is
// out of the felt range (0 <= x < 2²⁵¹ + 17·2¹⁹² + 1), it panics
func (f *Felt) SetBytes(bytes []byte) *Felt {
	bigInteger := ((*big.Int)(f)).SetBytes(bytes)
	checkFeltRange(bigInteger)
	return f
}

// SetBigInt sets a Felt's value from a big.Int, if the input is
// out of the felt range (0 <= x < 2²⁵¹ + 17·2¹⁹² + 1), it panics
func (f *Felt) SetBigInt(bigInteger *big.Int) *Felt {
	checkFeltRange(bigInteger)
	(*big.Int)(f).Set(bigInteger)
	return f
}

// SetInt64 sets a Felt's value from an int64
func (f *Felt) SetInt64(i int64) *Felt {
	((*big.Int)(f)).SetInt64(i)
	return f
}

// String returns a string representation of the Felt
func (f *Felt) String() string {
	return fmt.Sprintf("%v", (*big.Int)(f))
}

// checkFeltRange checks if a big.Int is in the felt range (0 <= x <= 2²⁵¹ + 17·2¹⁹²)
// and returns an error if it is not
func checkFeltRange(bigInteger *big.Int) error {
	if bigInteger.Cmp(bottomLimit) == -1 || bigInteger.Cmp(topLimit) == 1 {
		return fmt.Errorf("integer %d is not in the felt range [%d, %d)", bigInteger, bottomLimit, topLimit)
	}
	return nil
}

// transformLength transforms a byte slice to a 32 byte array
func transformLength(bytes []byte) [size]byte {
	if len(bytes) < size {
		newBytes := make([]byte, size)
		copy(newBytes[size-len(bytes):], bytes)
		bytes = newBytes
	}
	return *(*[32]byte)(bytes)
}

// Bytes32 returns a 32 byte array representation of the Felt
func (f *Felt) Bytes32() [size]byte {
	byteSlice := (*big.Int)(f).Bytes()
	return transformLength(byteSlice)
}
