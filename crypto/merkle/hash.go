package merkle

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/abstractions"
	"github.com/tendermint/tendermint/crypto/tmhash"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/pedersen"
)

// TODO: make these have a large predefined capacity
// we need 32 byte long "felts", it this is how we simulate felts here.
var (
	leafPrefix     = append(make([]byte, 15), []byte{0}...)
	leafPrefixFelt = append(make([]byte, 31), []byte{0}...)

	innerPrefix = append(make([]byte, 31), []byte{1}...)
)

// returns tmhash(<empty>)
func emptyHash() []byte {
	return crypto.ChecksumFelt([]byte{})
}

// returns tmhash(felt(0x00) || leaf)
func leafHash(leaf []byte) []byte {
	a := make([]byte, 16)
	copy(a, leafPrefix)
	b := crypto.Checksum(append(a, pedersen.ByteRounder(leaf)...))
	return b
}

// returns tmhash(felt(0x00) || leaf)
func leafHashFelt(leaf []byte) []byte {
	a := make([]byte, 32)
	copy(a, leafPrefixFelt)
	b := crypto.ChecksumFelt(append(a, pedersen.ByteRounder(leaf)...))
	return b
}

// returns tmhash(felt(0x00) || leaf)
func leafHashOpt(s hash.Hash, leaf []byte) []byte {
	s.Reset()
	s.Write(leafPrefix)
	s.Write(pedersen.ByteRounder(leaf))
	return s.Sum(nil)
}

func leafHashOptFelt(s hash.Hash, leaf []byte) []byte {
	s.Reset()
	s.Write(leafPrefixFelt)
	s.Write(pedersen.ByteRounder(leaf))
	return s.Sum(nil)
}

// returns tmhash(0x01 || left || right)
func innerHash(left []byte, right []byte) []byte {
	roundedLeft := pedersen.ByteRounder(left)
	roundedRight := pedersen.ByteRounder(right)

	data := make([]byte, len(innerPrefix)+len(roundedLeft)+len(roundedRight))
	n := copy(data, innerPrefix)
	n += copy(data[n:], roundedLeft)
	copy(data[n:], roundedRight)
	return crypto.ChecksumFelt(data)[:]
}

func innerHashOpt(s hash.Hash, left []byte, right []byte) []byte {
	s.Reset()
	s.Write(innerPrefix)
	s.Write(left)
	s.Write(right)
	return s.Sum(nil)
}
