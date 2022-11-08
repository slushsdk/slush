// This is the general hash function abstraction layer, we also add hashing for felt arrays, and single numbers (int128 and felts)
package pedersenInt128

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

const Size = 32

type PedersenHashInt128 struct {
	Input []byte
}

func New() hash.Hash {
	return new(PedersenHashInt128)
}

// Hashes b
func Sum256(b []byte) [32]byte {
	ph := new(PedersenHashInt128)
	ph.Write(b)

	var res [32]byte
	copy(res[:], ph.Sum(nil))
	return res
}

func HashInt128(b [16]byte) [32]byte {
	var res [32]byte
	x := pedersen.PedersenHashInt128(b)
	copy(res[:], pedersen.ByteRounderInt128(x[:]))
	return res
}

func HashFelt(b [32]byte) [32]byte {
	var res [32]byte
	x := pedersen.PedersenHashFelt(b)
	copy(res[:], x[:])
	return res
}

func (ph *PedersenHashInt128) Sum(b []byte) []byte {
	bs := pedersen.PedersenHashInt128Array(ph.Input)
	return append(b, pedersen.ByteRounderInt128(bs[:])...)
}

func (ph *PedersenHashInt128) BlockSize() int {
	return Size
}

func (ph *PedersenHashInt128) Size() int {
	return len(ph.Input)
}

func (ph *PedersenHashInt128) Reset() {
	ph.Input = []byte{}
}

func (ph *PedersenHashInt128) Write(p []byte) (n int, err error) {
	ph.Input = append(ph.Input, p...)
	return len(ph.Input), nil
}
