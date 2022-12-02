package utils

// ByteRounder returns a function that rounds up a byte slice to a multiply of
// the given size by appending zeros to the front of the slice.
func ByteRounder(roundingSize int) func([]byte) []byte {
	return func(ba []byte) []byte {
		rem := len(ba) % roundingSize
		rem = (roundingSize - rem) % roundingSize
		return append(make([]byte, rem), ba...)
	}
}
