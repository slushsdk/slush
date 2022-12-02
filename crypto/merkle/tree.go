package merkle

import (
	"hash"
	"math/bits"

	"github.com/tendermint/tendermint/crypto"
)

// HashFromByteSlicesInt128 computes a Merkle tree where the leaves are the byte slice,
// in the provided order. It follows RFC-6962.
func HashFromByteSlicesInt128(items [][]byte) []byte {
	return hashFromByteSlices(crypto.New128(), items)
}

func hashFromByteSlices(hasher hash.Hash, items [][]byte) []byte {
	switch len(items) {
	case 0:
		return emptyHash()
	case 1:
		return leafHashOpt(hasher, items[0])
	default:
		k := getSplitPoint(int64(len(items)))
		var left, right []byte
		if len(items) >= 4 {
			hasher2 := crypto.New128()

			leftChan := make(chan []byte)
			rightChan := make(chan []byte)

			parallelhashFromByteSlicesFelt := func(hashing hash.Hash, itemsList [][]byte, ch chan []byte) {
				ch <- hashFromByteSlicesFelt(hashing, itemsList)
			}

			leftItems := [][]byte{}
			leftItems = append(leftItems, items[:k]...)

			go parallelhashFromByteSlicesFelt(hasher, leftItems, leftChan)
			go parallelhashFromByteSlicesFelt(hasher2, items[k:], rightChan)

			left = <-leftChan
			right = <-rightChan
		} else {
			left = hashFromByteSlicesFelt(hasher, items[:k])
			right = hashFromByteSlicesFelt(hasher, items[k:])
		}

		return innerHashOpt(hasher, left, right)
	}
}
func HashFromByteSlicesFelt(items [][]byte) []byte {
	return hashFromByteSlicesFelt(crypto.NewFelt(), items)
}

func hashFromByteSlicesFelt(hasher hash.Hash, items [][]byte) []byte {
	switch len(items) {
	case 0:
		return emptyHash()
	case 1:
		return leafHashOptFelt(hasher, items[0])
	default:
		k := getSplitPoint(int64(len(items)))
		var left, right []byte
		if len(items) >= 4 {
			hasher2 := crypto.NewFelt()

			leftChan := make(chan []byte)
			rightChan := make(chan []byte)

			parallelhashFromByteSlicesFelt := func(hashing hash.Hash, itemsList [][]byte, ch chan []byte) {
				ch <- hashFromByteSlicesFelt(hashing, itemsList)
			}

			leftItems := [][]byte{}
			leftItems = append(leftItems, items[:k]...)

			go parallelhashFromByteSlicesFelt(hasher, leftItems, leftChan)
			go parallelhashFromByteSlicesFelt(hasher2, items[k:], rightChan)

			left = <-leftChan
			right = <-rightChan
		} else {
			left = hashFromByteSlicesFelt(hasher, items[:k])
			right = hashFromByteSlicesFelt(hasher, items[k:])
		}

		return innerHashOpt(hasher, left, right)
	}
}

// HashFromByteSliceIterative is an iterative alternative to
// HashFromByteSlice motivated by potential performance improvements.
// (#2611) had suggested that an iterative version of
// HashFromByteSlice would be faster, presumably because
// we can envision some overhead accumulating from stack
// frames and function calls. Additionally, a recursive algorithm risks
// hitting the stack limit and causing a stack overflow should the tree
// be too large.
//
// Provided here is an iterative alternative, a test to assert
// correctness and a benchmark. On the performance side, there appears to
// be no overall difference:
//
// BenchmarkHashAlternatives/recursive-4                20000 77677 ns/op
// BenchmarkHashAlternatives/iterative-4                20000 76802 ns/op
//
// On the surface it might seem that the additional overhead is due to
// the different allocation patterns of the implementations. The recursive
// version uses a single [][]byte slices which it then re-slices at each level of the tree.
// The iterative version reproduces [][]byte once within the function and
// then rewrites sub-slices of that array at each level of the tree.
//
// Experimenting by modifying the code to simply calculate the
// hash and not store the result show little to no difference in performance.
//
// These preliminary results suggest:
//
//  1. The performance of the HashFromByteSlice is pretty good
//  2. Go has low overhead for recursive functions
//  3. The performance of the HashFromByteSlice routine is dominated
//     by the actual hashing of data
//
// Although this work is in no way exhaustive, point #3 suggests that
// optimization of this routine would need to take an alternative
// approach to make significant improvements on the current performance.
//
// Finally, considering that the recursive implementation is easier to
// read, it might not be worthwhile to switch to a less intuitive
// implementation for so little benefit.
func HashFromByteSlicesIterative(input [][]byte) []byte {
	items := make([][]byte, len(input))
	hasher := crypto.New128()
	for i, leaf := range input {
		items[i] = leafHash(leaf)
	}

	size := len(items)
	for {
		switch size {
		case 0:
			return emptyHash()
		case 1:
			return items[0]
		default:
			rp := 0 // read position
			wp := 0 // write position
			for rp < size {
				if rp+1 < size {
					items[wp] = innerHashOpt(hasher, items[rp], items[rp+1])
					rp += 2
				} else {
					items[wp] = items[rp]
					rp++
				}
				wp++
			}
			size = wp
		}
	}
}

// getSplitPoint returns the largest power of 2 less than length
func getSplitPoint(length int64) int64 {
	if length < 1 {
		panic("Trying to split a tree with size < 1")
	}
	uLength := uint(length)
	bitlen := bits.Len(uLength)
	k := int64(1 << uint(bitlen-1))
	if k == length {
		k >>= 1
	}
	return k
}
