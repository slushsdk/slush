package abstractions

import (
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
