package crypto

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/pedersen"

	"github.com/tendermint/tendermint/internal/jsontypes"
	"github.com/tendermint/tendermint/libs/bytes"
)

const (
	// HashSize is the size in bytes of an AddressHash.
	HashSize = 32

	// AddressSize is the size of a pubkey address.
	AddressSize = 32
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = bytes.HexBytes

// AddressHash computes a truncated SHA-256 hash of bz for use as
// a peer address.
//
// See: https://docs.tendermint.com/master/spec/core/data_structures.html#address
func AddressHash(bz []byte) Address {
	h := pedersen.Sum(bz)
	size := AddressSize
	if size <= 32 {
		return Address(h[:size])
	}

	return Address(h[:32])
}

// NewFelt returns a new pedersen hasher that expects a byte chunk
// containing 32 length felt byte slices
func NewFelt() hash.Hash {
	return pedersen.New()
}

// New128 returns a new pedersen hasher that expects a byte chunk
// containing 16 length felt byte slices
func New128() hash.Hash {
	return pedersen.New128()
}

// Checksum returns the pedersen of the bz.
func Checksum128(in []byte) []byte {
	hash := pedersen.Sum128(in)
	return hash[:]
}

// Checksum returns the SHA256 of the bz.
func ChecksumFelt(in []byte) []byte {
	hash := pedersen.Sum(in)
	return hash[:]
}

func Sum128(in []byte) [HashSize]byte {
	return pedersen.Sum128(in)
}

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifySignature(msg []byte, sig []byte) bool
	Equals(PubKey) bool
	Type() string

	// Implementations must support tagged encoding in JSON.
	jsontypes.Tagged
}

type PrivKey interface {
	Bytes() []byte
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
	Type() string

	// Implementations must support tagged encoding in JSON.
	jsontypes.Tagged
}

type Symmetric interface {
	Keygen() []byte
	Encrypt(plaintext []byte, secret []byte) (ciphertext []byte)
	Decrypt(ciphertext []byte, secret []byte) (plaintext []byte, err error)
}

// If a new key type implements batch verification,
// the key type must be registered in github.com/tendermint/tendermint/crypto/batch
type BatchVerifier interface {
	// Add appends an entry into the BatchVerifier.
	Add(key PubKey, message, signature []byte) error
	// Verify verifies all the entries in the BatchVerifier, and returns
	// if every signature in the batch is valid, and a vector of bools
	// indicating the verification status of each signature (in the order
	// that signatures were added to the batch).
	Verify() (bool, []bool)
}
