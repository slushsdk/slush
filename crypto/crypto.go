package crypto

import (
	"hash"

	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/pedersen/pedersenInt128"

	"github.com/tendermint/tendermint/crypto/pedersen/pedersenFelt"

	"github.com/tendermint/tendermint/internal/jsontypes"
	"github.com/tendermint/tendermint/libs/bytes"
)

const (
	// HashSize is the size in bytes of an AddressHash.
	HashSize = pedersenInt128.Size

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
	h := Sum256Felt(bz)
	size := AddressSize
	if size <= 32 {
		return Address(h[:size])
	}

	return Address(h[:32])
}

func NewInt128() hash.Hash {
	return pedersenInt128.New()
}

// Hashes b
func Sum256Int128(b []byte) [32]byte {
	return pedersenInt128.Sum256(b)
}

// Checksum returns the SHA256 of the bz.
func ChecksumInt128(bz []byte) []byte {
	h := Sum256Int128(bz)
	return h[:]
}

func NewFelt() hash.Hash {
	return pedersenFelt.New()
}

// Hashes b
func Sum256Felt(b []byte) [32]byte {
	return pedersenFelt.Sum256(b)
}

// Checksum returns the SHA256 of the bz.
func ChecksumFelt(bz []byte) []byte {
	h := pedersenFelt.Sum256(bz)
	return h[:]
}

func HashInt128(b [16]byte) [32]byte {
	return pedersenInt128.HashInt128(b)
}

func HashFelt(b [32]byte) [32]byte {
	return pedersenFelt.HashFelt(b)
}

func ByteRounder(b []byte) []byte {
	return pedersen.ByteRounder(b)
}

func ByteRounderFelt(b []byte) []byte {
	return pedersen.ByteRounderFelt(b)
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
