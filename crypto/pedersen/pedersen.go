package pedersen

// implementation of hash.Hash interface

import (
	"crypto/rand"
	"hash"
	"math/big"

	"github.com/tendermint/tendermint/crypto/pedersen/felt"
	"github.com/tendermint/tendermint/crypto/pedersen/hashing"
	"github.com/tendermint/tendermint/crypto/utils"
)

// The size of a pedersen checksum
const Size = 32

// The blocksize of pedersen
const BlockSize = 32

// The blocksize of pedersen128
const BlockSize128 = 16

type pedersenHash struct {
	input []*felt.Felt
	is128 bool
}

// New creates a pedersenHash (with the BlockSize of 32)
// which implements the hash.Hash interface
func New() hash.Hash {
	ph := new(pedersenHash)
	ph.Reset()
	return ph
}

// New128 creates a pedersenHash (with the BlockSize of 16)
// which implements the hash.Hash interface
func New128() hash.Hash {
	ph := new(pedersenHash)
	ph.Reset()
	ph.is128 = true
	return ph
}

// Size returns the size of the pedersenHash's checksum
func (ph *pedersenHash) Size() int {
	return Size
}

// BlockSize returns the pederesenHash's BlockSize
func (ph *pedersenHash) BlockSize() int {
	if ph.is128 {
		return BlockSize128
	}
	return BlockSize
}

// Reset resets the pedersenHash's input to an empty Felt slice
func (ph *pedersenHash) Reset() {
	var empty []*felt.Felt
	ph.input = empty
}

// getFeltsFromBytes returns a function that splits the input
// into chunks of the given length and converts these chunks
// to Felts
func getFeltsFromBytes(blockSize int) func(bytes []byte) []*felt.Felt {
	return func(bytes []byte) []*felt.Felt {
		rounded := utils.ByteRounder(blockSize)(bytes)

		chunks := utils.Split(rounded, blockSize)

		feltSlice := make([]*felt.Felt, len(chunks))
		for i, chunk := range chunks {
			feltSlice[i] = felt.New().SetBytes(chunk)
		}
		return feltSlice
	}
}

// Write splits the input either into 32 or 16 length byte chunks
// (depending on the BlockSize), converts them to Felts and
// appends these Felts to the pedersenHash's input
func (ph *pedersenHash) Write(input []byte) (int, error) {
	if ph.is128 {
		ph.input = append(ph.input, getFeltsFromBytes(BlockSize128)(input)...)
	} else {
		ph.input = append(ph.input, getFeltsFromBytes(BlockSize)(input)...)
	}
	return len(input), nil
}

// checkSum returns the fixed length (32 bytes) hash of the
// pedersenHash's input
func (ph *pedersenHash) checkSum() [Size]byte {
	return hashing.Hash(ph.input...).Bytes32()
}

// Sum appends the checksum of the pedersenHash's input to the
// bytes slice that was passed in and returns the resulting slice
func (ph *pedersenHash) Sum(in []byte) []byte {
	hash := ph.checkSum()
	return append(in, hash[:]...)
}

// Sum splits the input into 32 length byte chunks and returns
// the fixed length (32 bytes) checksum of these chunks
func Sum(data []byte) [Size]byte {
	var ph pedersenHash
	ph.Reset()
	ph.Write(data)
	return ph.checkSum()
}

// Sum128 splits the input into 16 length byte chunks and returns
// the fixed length (32 bytes) checksum of these chunks
func Sum128(data []byte) [Size]byte {
	var ph pedersenHash
	ph.Reset()
	ph.is128 = true
	ph.Write(data)
	return ph.checkSum()
}

func ByteRounderFactory(n int) func(byteSlice []byte) []byte {
	return func(byteSlice []byte) []byte {
		rem := len(byteSlice) % n
		rem = (n - rem) % n
		byteSliceRounded := append(make([]byte, rem), byteSlice...)
		return byteSliceRounded
	}
}

func RandFeltBytes(n int) []byte {
	numb, _ := big.NewInt(0).SetString("3618502788666131213697322783095070105623107215331596699973092056135872020480", 10)
	randNumb, _ := rand.Int(rand.Reader, numb)
	randBytes := randNumb.Bytes()

	randBytesRounded := ByteRounderFactory(n)(randBytes)

	return randBytesRounded[:n]
}
