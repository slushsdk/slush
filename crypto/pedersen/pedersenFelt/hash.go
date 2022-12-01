// This is the general hash function abstraction layer, we also add hashing for felt arrays, and single numbers (int128 and felts)
package pedersenFelt

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

const Size = 32

type PedersenHashFelt struct {
	Input []byte
}

func New() hash.Hash {
	return new(PedersenHashFelt)
}

// expects felts packed to 256 bits in b
func Sum256(b []byte) [32]byte {

	var res [32]byte
	x := pedersen.PedersenHashFeltArray(b)
	copy(res[:], x[:])
	return res
}

func HashFelt(b [32]byte) [32]byte {
	var res [32]byte
	x := pedersen.PedersenHashFelt(b)
	copy(res[:], x[:])
	return res
}

func (ph *PedersenHashFelt) Sum(b []byte) []byte {
	bs := pedersen.PedersenHashFeltArray(ph.Input)
	return append(b, pedersen.ByteRounderFelt(bs[:])...)
}

func (ph *PedersenHashFelt) BlockSize() int {
	return Size
}

func (ph *PedersenHashFelt) Size() int {
	return len(ph.Input)
}

func (ph *PedersenHashFelt) Reset() {
	ph.Input = []byte{}
}

func (ph *PedersenHashFelt) Write(p []byte) (n int, err error) {
	ph.Input = append(ph.Input, p...)
	return len(ph.Input), nil
}
