package abstractions

import (
	"bytes"
	sha256 "crypto/sha256"
	"hash"
)

const Size = sha256.Size

func New() hash.Hash {
	return sha256.New()
}

func Sum256(b []byte) [32]byte {
	r := sha256.Sum256(b)
	return r
}

//We want to pass in 64 bit numbers to pedersen, so we want to round the byte array to be that long.
func ByteRounder(ba []byte) []byte {

	rem := len(ba) % 8
	return bytes.Join([][]byte{ba, make([]byte, rem)}, make([]byte, 0))

}
