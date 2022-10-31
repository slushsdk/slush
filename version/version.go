package version

import (
	encoding_binary "encoding/binary"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	tmversion "github.com/tendermint/tendermint/proto/tendermint/version"
)

var (
	TMVersion = TMVersionDefault
)

const (

	// TMVersionDefault is the used as the fallback version of Tendermint Core
	// when not using git describe. It is formatted with semantic versioning.
	TMVersionDefault = "0.35.0-unreleased"
	// ABCISemVer is the semantic version of the ABCI library
	ABCISemVer = "0.17.0"

	ABCIVersion = ABCISemVer
)

var (
	// P2PProtocol versions all p2p behavior and msgs.
	// This includes proposer selection.
	P2PProtocol uint64 = 8

	// BlockProtocol versions all block data structures and processing.
	// This includes validity of blocks and state updates.
	BlockProtocol uint64 = 11
)

type Consensus struct {
	Block uint64 `json:"block,string"`
	App   uint64 `json:"app,string"`
}

func (c Consensus) ToProto() tmversion.Consensus {
	return tmversion.Consensus{
		Block: c.Block,
		App:   c.App,
	}
}

func (c Consensus) Hash() []byte {

	cByte := make([]byte, 16)

	blockByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(blockByte, uint64(c.Block))

	appByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(appByte, uint64(c.App))

	cByte = append(blockByte, appByte...)

	return tmcrypto.ChecksumInt128(cByte)
}
