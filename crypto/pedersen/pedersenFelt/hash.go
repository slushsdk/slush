//This is the general hash function abstraction layer, we also add hashing for felt arrays, and single numbers (int128 and felts)
package pedersenFelt

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

const Size = 32

func New() hash.Hash {
	return new(pedersen.PedersenHash)
}

//expects felts packed to 256 bits in b
func Sum256(b []byte) [32]byte {

	var res [32]byte
	copy(res[:], pedersen.ByteRounder(pedersen.PedersenHashFeltArray(b)))
	return res
}

func HashFelt(b [32]byte) [32]byte {
	var res [32]byte
	copy(res[:], pedersen.ByteRounder(pedersen.PedersenHashFelt(b)))
	return res
}
