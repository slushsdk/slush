// Package pedersen implements the StarkNet variant of the Pedersen
// hash function.
package pedersen

import (
	_ "embed"
	"fmt"
	"math/big"

	"github.com/tendermint/tendermint/crypto/utils"
)

type PedersenHash struct {
	input []byte
}

//This appends the hash to b. Notable, we
func (ph *PedersenHash) Sum(b []byte) []byte {

	return append(b, ByteRounder(pedersenHashInt128Array(ph.input))...)
}

//We want to pass in 128 bit numbers from pedersen, so we want to round the byte array to be that long.
// Checking is also done inside pedersen.
func ByteRounder(ba []byte) []byte {

	rem := len(ba) % 16
	//Taking reminder with 16 only changes rem if it was originally 0.
	rem = (16 - rem) % 16
	return append(make([]byte, rem), ba...)

}

//We want to pass in 128 bit numbers from pedersen, so we want to round the byte array to be that long.
// Checking is also done inside pedersen.
func ByteRounderFelt(ba []byte) []byte {

	rem := len(ba) % 32
	//Taking reminder with 16 only changes rem if it was originally 0.
	rem = (16 - rem) % 32
	return append(make([]byte, rem), ba...)

}

func (ph *PedersenHash) BlockSize() int {
	return 32
}

func (ph *PedersenHash) Size() int {
	return len(ph.input)
}

func (ph *PedersenHash) Reset() {
	ph.input = []byte{}
}

func (ph *PedersenHash) Write(p []byte) (n int, err error) {
	ph.input = append(ph.input, p...)
	return len(ph.input), nil
}

func pedersenHashInt128(b [16]byte) []byte {
	return Digest(big.NewInt(0).SetBytes(b[:]), big.NewInt(0)).Bytes()
}

func pedersenHashInt128Array(b []byte) []byte {
	chunks := utils.Split(b, 16)

	if len(chunks) == 0 {
		return Digest(big.NewInt(0), big.NewInt(0)).Bytes()
	}
	lastWordSize := len(chunks[len(chunks)-1])
	isLastWordFull := lastWordSize == 16

	if !isLastWordFull {
		remainingBytes := 16 - lastWordSize
		leadingBytes := make([]byte, remainingBytes)
		chunks[len(chunks)-1] = append(leadingBytes, chunks[len(chunks)-1]...)
	}

	pedersenInput := make([]*big.Int, len(chunks))

	for i := 0; i < len(chunks); i++ {
		pedersenInput[i] = big.NewInt(0).SetBytes((chunks[i]))
	}

	pedersenOutput := ArrayDigest(pedersenInput...)
	pedersenOutputBytes := pedersenOutput.Bytes()
	return pedersenOutputBytes
}

func pedersenHashFelt(b [32]byte) []byte {
	return (Digest(big.NewInt(0).SetBytes(b[:]), big.NewInt(0)).Bytes())
}

func pedersenHashFeltArray(b []byte) []byte {
	chunks := utils.Split(b, 32)

	if len(chunks) == 0 {
		return Digest(big.NewInt(0), big.NewInt(0)).Bytes()
	}
	lastWordSize := len(chunks[len(chunks)-1])
	isLastWordFull := lastWordSize == 32

	if !isLastWordFull {
		remainingBytes := 32 - lastWordSize
		leadingBytes := make([]byte, remainingBytes)
		chunks[len(chunks)-1] = append(leadingBytes, chunks[len(chunks)-1]...)
	}

	pedersenInput := make([]*big.Int, len(chunks))

	for i := 0; i < len(chunks); i++ {
		pedersenInput[i] = big.NewInt(0).SetBytes((chunks[i]))
	}

	pedersenOutput := ArrayDigest(pedersenInput...)
	pedersenOutputBytes := pedersenOutput.Bytes()
	return pedersenOutputBytes
}

// Digest returns a field element that is the result of hashing an input
// (a, b) ∈ 𝔽²ₚ where p = 2²⁵¹ + 17·2¹⁹² + 1. This function will panic
// if len(data) > 2. In order to hash n > 2 items, use ArrayDigest.
func Digest(data ...*big.Int) *big.Int {
	n := len(data)
	if n > 2 {
		panic("attempted to hash more than 2 field elements")
	}

	// Make a defensive copy of the input data.
	elements := make([]*big.Int, n)
	for i, e := range data {
		elements[i] = new(big.Int).Set(e)
	}

	zero := new(big.Int)
	// Shift point.
	pt1 := points[0]
	for i, x := range elements {
		if x.Cmp(zero) == -1 || x.Cmp(prime) == 1 {
			panic(fmt.Sprintf("%x is not in the range 0 <= x < 2²⁵¹ + 17·2¹⁹² + 1", x))
		}
		for j := 0; j < 252; j++ {
			// Create a copy because *big.Int.And mutates.
			copyX := new(big.Int).Set(x)
			if copyX.And(copyX, big.NewInt(1)).Cmp(zero) != 0 {
				pt1.add(&points[2+i*252+j])
			}
			x.Rsh(x, 1)
		}
	}
	return pt1.x
}

// ArrayDigest returns a field element that is the result of hashing an
// array of field elements. This is generally used to overcome the
// limitation of the Digest function which has an upper bound on the
// amount of field elements that can be hashed. See the array hashing
// section of the StarkNet documentation https://docs.starknet.io/docs/Hashing/hash-functions#array-hashing
// for more details.
func ArrayDigest(data ...*big.Int) *big.Int {
	digest := new(big.Int)
	for _, item := range data {
		digest = Digest(digest, item)
	}
	return Digest(digest, big.NewInt(int64(len(data))))
}
