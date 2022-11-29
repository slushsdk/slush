package abstractions

import (
	sha256 "crypto/sha256"
	"encoding/binary"
	"hash"
	"math/big"

	"github.com/tendermint/tendermint/crypto/pedersen"
)

const Size = sha256.Size

func New() hash.Hash {
	return sha256.New()
}

func Sum256(b []byte) [32]byte {
	r := sha256.Sum256(b)
	return r
}

func pedersenHash(b []byte) (result [32]byte) {
	chunks := split(b, 31)

	pedersenInput := make([]*big.Int, len(chunks))

	for i := 0; i < len(chunks); i++ {
		pedersenInput[i] = big.NewInt(int64(binary.BigEndian.Uint64(chunks[i])))
	}

	pedersenOutput := pedersen.ArrayDigest(pedersenInput...)
	pedersenOutputBytes := pedersenOutput.Bytes()
	copy(result[:], pedersenOutputBytes)
	return result
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}
