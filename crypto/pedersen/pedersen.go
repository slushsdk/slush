// Package pedersen implements the StarkNet variant of the Pedersen
// hash function.
package pedersen

import (
	"crypto/rand"
	_ "embed"
	"math/big"

	"github.com/tendermint/tendermint/crypto/utils"
)

func ByteRounderFelt(ba []byte) []byte {
	rem := len(ba) % 32
	// Taking reminder with 32 only changes rem if it was originally 0.
	rem = (32 - rem) % 32
	return append(make([]byte, rem), ba...)
}

func PedersenHashFelt(b [32]byte) [32]byte {
	bigInteger := big.NewInt(0).SetBytes(b[:])
	zero := big.NewInt(0)
	pedersenOutputBytes := ByteRounderFelt(Digest(bigInteger, zero).Bytes())
	return *(*[32]byte)(pedersenOutputBytes)
}

func PedersenHashFeltArray(b []byte) [32]byte {
	chunks := utils.Split(b, 32)

	if len(chunks) == 0 {
		zero := big.NewInt(0)
		pedersenOutputBytes := ByteRounderFelt(Digest(zero, zero).Bytes())
		return *(*[32]byte)(pedersenOutputBytes)
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
	pedersenOutputBytes := ByteRounderFelt(pedersenOutput.Bytes())
	return *(*[32]byte)(pedersenOutputBytes)
}

func ByteRounderFactory(n int) func(byteSlice []byte) []byte {
	return func(byteSlice []byte) []byte {
		rem := len(byteSlice) % n
		rem = (n - rem) % n
		byteSliceRounded := append(make([]byte, rem), byteSlice...)
		return byteSliceRounded
	}
}

func FeltBytes(n int) []byte {
	numb, _ := big.NewInt(0).SetString("3618502788666131213697322783095070105623107215331596699973092056135872020480", 10)
	randNumb, _ := rand.Int(rand.Reader, numb)
	randBytes := randNumb.Bytes()

	randBytesRounded := ByteRounderFactory(n)(randBytes)

	return randBytesRounded[:n]
}
