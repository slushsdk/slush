package abstractions

import (

	// tmhash "crypto/sha256"
	"hash"

	tmhash "github.com/tendermint/tendermint/crypto/pedersen"
)

const Size = tmhash.Size

func New() hash.Hash {
	return tmhash.New()
}

func Sum256(b []byte) [32]byte {
	r := tmhash.Sum256(b)
	return r
}

//We want to pass in 64 bit numbers to pedersen, so we want to round the byte array to be that long.
func ByteRounder(ba []byte) []byte {
	//we add len
	rem := len(ba) % 8
	rem = (8 - rem) % 8
	return append(make([]byte, rem), ba...)

}
