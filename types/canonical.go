package types

import (
	"bytes"
	"encoding/binary"
	encoding_binary "encoding/binary"
	time "time"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/utils"
	tmtime "github.com/tendermint/tendermint/libs/time"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

// Canonical* wraps the structs in types for amino encoding them for use in SignBytes / the Signable interface.

// TimeFormat is used for generating the sigs
const TimeFormat = time.RFC3339Nano

//-----------------------------------
// Canonicalize the structs

func CanonicalizeBlockID(bid tmproto.BlockID) *tmproto.CanonicalBlockID {
	rbid, err := BlockIDFromProto(&bid)
	if err != nil {
		panic(err)
	}
	var cbid *tmproto.CanonicalBlockID
	if rbid == nil || rbid.IsZero() {
		cbid = nil
	} else {
		cbid = &tmproto.CanonicalBlockID{
			Hash:          bid.Hash,
			PartSetHeader: CanonicalizePartSetHeader(bid.PartSetHeader),
		}
	}

	return cbid
}

// CanonicalizeVote transforms the given PartSetHeader to a CanonicalPartSetHeader.
func CanonicalizePartSetHeader(psh tmproto.PartSetHeader) tmproto.CanonicalPartSetHeader {
	return tmproto.CanonicalPartSetHeader(psh)
}

// CanonicalizeVote transforms the given Proposal to a CanonicalProposal.
func CanonicalizeProposal(chainID string, proposal *tmproto.Proposal) tmproto.CanonicalProposal {
	return tmproto.CanonicalProposal{
		Type:      tmproto.ProposalType,
		Height:    proposal.Height,       // encoded as sfixed64
		Round:     int64(proposal.Round), // encoded as sfixed64
		POLRound:  int64(proposal.PolRound),
		BlockID:   CanonicalizeBlockID(proposal.BlockID),
		Timestamp: proposal.Timestamp,
		ChainID:   chainID,
	}
}

// CanonicalizeVote transforms the given Vote to a CanonicalVote, which does
// not contain ValidatorIndex and ValidatorAddress fields.
func CanonicalizeVote(chainID string, vote *tmproto.Vote) tmproto.CanonicalVote {
	return tmproto.CanonicalVote{
		Type:      vote.Type,
		Height:    vote.Height,       // encoded as sfixed64
		Round:     int64(vote.Round), // encoded as sfixed64
		BlockID:   CanonicalizeBlockID(vote.BlockID),
		Timestamp: vote.Timestamp,
		ChainID:   chainID,
	}
}

// CanonicalTime can be used to stringify time in a canonical way.
func CanonicalTime(t time.Time) string {
	// Note that sending time over amino resets it to
	// local time, we need to force UTC here, so the
	// signatures match
	return tmtime.Canonical(t).Format(TimeFormat)
}

func HashCanonicalVoteNoTime(canVote tmproto.CanonicalVote) []byte {

	typeByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(typeByte, uint64(canVote.Type))

	heightByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(heightByte, uint64(canVote.Height))

	roundByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(roundByte, uint64(canVote.Round))

	var blockIDHash []byte
	if canVote.BlockID == nil {
		blockIDHash = []byte{}
	} else {
		blockIDHash = HashBlockID(*canVote.GetBlockID())
	}

	//timestampHash := HashTime(canVote.Timestamp)

	chainIDByte := utils.ByteRounder(16)([]byte(canVote.ChainID))

	typeByteHashArray := crypto.Checksum128(typeByte)

	heightByteHashArray := crypto.Checksum128(heightByte)

	roundByteHashArray := crypto.Checksum128(roundByte)

	chainIDByteHashArray := crypto.Checksum128(chainIDByte)

	voteArray := bytes.Join([][]byte{typeByteHashArray[:], heightByteHashArray[:], roundByteHashArray[:], blockIDHash, chainIDByteHashArray[:]}, make([]byte, 0))

	r := crypto.ChecksumFelt(voteArray)
	return r
}

func HashTime(timeStamp time.Time) []byte {

	timeb := make([]byte, 8)
	binary.BigEndian.PutUint64(timeb, uint64(timeStamp.UnixNano()))
	time_ret := crypto.Checksum128(timeb)
	return time_ret[:]

}

func HashBlockID(m tmproto.CanonicalBlockID) []byte {
	mHashCopy := make([]byte, 32)
	copy(mHashCopy, m.GetHash())
	toHash := append(mHashCopy, HashCPSetHeader(m.GetPartSetHeader())...)
	return crypto.ChecksumFelt(toHash)

}

func HashCPSetHeader(canPartSetHeader tmproto.CanonicalPartSetHeader) []byte {
	//The organising principle is for hashes we put it directly into the hasher,
	// for other formats we hash them seperately first

	totalb := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(totalb, uint64(canPartSetHeader.Total))
	totalb_hash := crypto.Checksum128(totalb)

	hashArray := append(totalb_hash[:], canPartSetHeader.Hash...)

	return crypto.ChecksumFelt(hashArray)
}
