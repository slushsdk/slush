package rand

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
)

const (
	strChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" // 62 characters
)

// Str constructs a random alphanumeric string of given length
// from math/rand's global default Source.
func Str(length int) string { return buildString(length, mrand.Int63) }

// StrFromSource produces a random string of a specified length from
// the specified random source.
func StrFromSource(r *mrand.Rand, length int) string { return buildString(length, r.Int63) }

func buildString(length int, picker func() int64) string {
	if length <= 0 {
		return ""
	}

	chars := make([]byte, 0, length)
	for {
		val := picker()
		for i := 0; i < 10; i++ {
			v := int(val & 0x3f) // rightmost 6 bits
			if v >= 62 {         // only 62 characters in strChars
				val >>= 6
				continue
			} else {
				chars = append(chars, strChars[v])
				if len(chars) == length {
					return string(chars)
				}
				val >>= 6
			}
		}
	}
}

// Bytes returns n random bytes generated from math/rand's global default Source.
func Bytes(n int) []byte {
	bs := make([]byte, n)
	for i := 0; i < len(bs); i++ {
		// nolint:gosec // G404: Use of weak random number generator
		bs[i] = byte(mrand.Int() & 0xFF)
	}
	return bs
}

func ByteRounderFactory(n int) func(byteSlice []byte) []byte {
	return func(byteSlice []byte) []byte {
		rem := len(byteSlice) % n
		rem = (n - rem) % n
		byteSliceRounded := append(make([]byte, rem), byteSlice...)
		return byteSliceRounded
	}
}

func FeltBytes(n int) []byte {
	numb, _ := big.NewInt(0).SetString("3618502788666131213697322783095070105623107215331596699973092056135872020480", 10)
	randNumb, _ := rand.Int(rand.Reader, numb)
	randBytes := randNumb.Bytes()

	randBytesRounded := ByteRounderFactory(n)(randBytes)

	return randBytesRounded[:n]
}
