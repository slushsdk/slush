//This is the general hash function abstraction layer, we also add hashing for felt arrays, and single numbers (int128 and felts)
package pedersenInt64

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

const Size = 32

func New() hash.Hash {
	return new(pedersen.PedersenHash)
}

//Hashes b
func Sum256(b []byte) [32]byte {
	ph := new(pedersen.PedersenHash)
	ph.Write(b)

	var res [32]byte
	copy(res[:], ph.Sum(nil))
	return res
}

//expects felts packed to 256 bits in b
func Sum256Felt(b []byte) [32]byte {

	var res [32]byte
	copy(res[:], pedersen.ByteRounder(pedersen.PedersenHashFeltArray(b)))
	return res
}

func HashInt128(b [16]byte) [32]byte {
	var res [32]byte
	copy(res[:], pedersen.ByteRounder(pedersen.PedersenHashInt128(b)))
	return res
}

func HashFelt(b [32]byte) [32]byte {
	var res [32]byte
	copy(res[:], pedersen.ByteRounder(pedersen.PedersenHashFelt(b)))
	return res
}
