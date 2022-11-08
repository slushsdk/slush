package pedersen

import (
	"math/big"

	"github.com/tendermint/tendermint/crypto/utils"
)

// We want to pass in 128 bit numbers from pedersen, so we want to round the byte array to be that long.
// Checking is also done inside pedersen.
func ByteRounderInt128(ba []byte) []byte {

	rem := len(ba) % 16
	//Taking reminder with 16 only changes rem if it was originally 0.
	rem = (16 - rem) % 16
	return append(make([]byte, rem), ba...)

}

func PedersenHashInt128(b [16]byte) [32]byte {
	bigInteger := big.NewInt(0).SetBytes(b[:])
	zero := big.NewInt(0)
	pedersenOutputBytes := ByteRounderFelt(Digest(bigInteger, zero).Bytes())
	return *(*[32]byte)(pedersenOutputBytes)
}

func PedersenHashInt128Array(b []byte) [32]byte {
	chunks := utils.Split(b, 16)

	if len(chunks) == 0 {
		zero := big.NewInt(0)
		pedersenOutputBytes := ByteRounderFelt(Digest(zero, zero).Bytes())
		return *(*[32]byte)(pedersenOutputBytes)
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
	pedersenOutputBytes := ByteRounderFelt(pedersenOutput.Bytes())
	return *(*[32]byte)(pedersenOutputBytes)
}
