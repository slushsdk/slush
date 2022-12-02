package hashing

import (
	_ "embed"
	"fmt"
	"math/big"

	"github.com/tendermint/tendermint/crypto/pedersen/felt"
)

// hash2 returns a field element that is the result of hashing two inputs
// ((a, b) ∈ 𝔽²ₚ where p = 2²⁵¹ + 17·2¹⁹² + 1). This function will panic if
// an input is not in the felt range (0 <= x < 2²⁵¹ + 17·2¹⁹² + 1).
func hash2(felt1, felt2 *felt.Felt) *felt.Felt {
	// Make a defensive copy of the input data.
	elements := make([]*big.Int, 2)
	elements[0] = new(big.Int).Set((*big.Int)(felt1))
	elements[1] = new(big.Int).Set((*big.Int)(felt2))

	zero := new(big.Int)

	// Shift point.
	pt1 := points[0]
	for i, x := range elements {
		if x.Cmp(zero) == -1 || x.Cmp(primeMinusOne) == 1 {
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
	return (*felt.Felt)(pt1.x)
}

// hashFelt returns a Felt that is the result of hashing an
// input (a ∈ 𝔽²ₚ where p = 2²⁵¹ + 17·2¹⁹² + 1) with zero.
func hashFelt(felt1 *felt.Felt) *felt.Felt {
	return hash2(felt1, felt.New())
}

// hashFeltArray returns a field element that is the result of hashing an
// array of field elements. This is generally used to overcome the
// limitation of the Hash2 function which has an upper bound on the
// amount of field elements that can be hashed. See the array hashing
// section of the StarkNet documentation
// https://docs.starknet.io/docs/Hashing/hash-functions#array-hashing
// for more details.
func hashFeltArray(data ...*felt.Felt) *felt.Felt {
	dig := new(felt.Felt)
	for _, item := range data {
		dig = hash2(dig, item)
	}
	dataLen := (*felt.Felt)(big.NewInt(int64(len(data))))
	return hash2(dig, dataLen)
}

// Hash decides which hash function to use based on the length of the
// input data. If the length of the input data is 0, Hash returns the
// HashFelt(0). If the length of the input data is 1, Hash returns
// HashFelt(input[0]). If the length of the input data is greater than 1,
// Hash returns HashFeltArray(data).
func Hash(data ...*felt.Felt) *felt.Felt {
	switch len(data) {
	case 0:
		return hashFelt(felt.New())
	case 1:
		return hashFelt(data[0])
	default:
		return hashFeltArray(data...)
	}
}
