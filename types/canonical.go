package types

import (
	"bytes"
	encoding_binary "encoding/binary"
	time "time"

	ihash "github.com/tendermint/tendermint/crypto/abstractions"
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
	if rbid == nil || rbid.IsNil() {
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
// not contain ValidatorIndex and ValidatorAddress fields, or any fields
// relating to vote extensions.
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

// CanonicalizeVoteExtension extracts the vote extension from the given vote
// and constructs a CanonicalizeVoteExtension struct, whose representation in
// bytes is what is signed in order to produce the vote extension's signature.
func CanonicalizeVoteExtension(chainID string, vote *tmproto.Vote) tmproto.CanonicalVoteExtension {
	return tmproto.CanonicalVoteExtension{
		Extension: vote.Extension,
		Height:    vote.Height,
		Round:     int64(vote.Round),
		ChainId:   chainID,
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
	hasherForType := ihash.New()
	hasherForType.Write(typeByte)

	heightByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(heightByte, uint64(canVote.Height))
	hasherForHeight := ihash.New()
	hasherForHeight.Write(heightByte)

	roundByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(roundByte, uint64(canVote.Round))
	hasherForRound := ihash.New()
	hasherForRound.Write(roundByte)

	var blockIDHash []byte
	if canVote.BlockID == nil {
		blockIDHash = []byte{}
	} else {
		blockIDHash = BlockIDHasher(*canVote.GetBlockID())
	}

	//timestampHash := HashTime(canVote.Timestamp)

	chainIDByte := ihash.ByteRounder([]byte(canVote.ChainID))
	hasherForChainID := ihash.New()
	hasherForChainID.Write(chainIDByte)

	var voteArray []byte
	voteArray = bytes.Join([][]byte{hasherForType.Sum(nil), hasherForHeight.Sum(nil), hasherForRound.Sum(nil), blockIDHash, hasherForChainID.Sum(nil)}, make([]byte, 0))
	hasher := ihash.New()
	hasher.Write(voteArray)
	r := hasher.Sum(nil)

	return r
}

func HashCanonicalVoteExtension(canVote tmproto.CanonicalVoteExtension) []byte {

	extensionByte := ihash.ByteRounder(canVote.Extension)
	hasherForExtension := ihash.New()
	hasherForExtension.Write(extensionByte)

	heightByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(heightByte, uint64(canVote.Height))
	hasherForHeight := ihash.New()
	hasherForHeight.Write(heightByte)

	roundByte := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(roundByte, uint64(canVote.Round))
	hasherForRound := ihash.New()
	hasherForRound.Write(roundByte)

	chainIDByte := ihash.ByteRounder([]byte(canVote.ChainId))
	hasherForChainID := ihash.New()
	hasherForChainID.Write(chainIDByte)

	var voteArray []byte
	voteArray = bytes.Join([][]byte{hasherForExtension.Sum(nil), hasherForHeight.Sum(nil), hasherForRound.Sum(nil), hasherForChainID.Sum(nil)}, make([]byte, 0))
	hasher := ihash.New()
	hasher.Write(voteArray)
	r := hasher.Sum(nil)

	return r
}

func HashTime(timeStamp time.Time) []byte {

	hasher := ihash.New()
	hasher.Write(ihash.ByteRounder([]byte(tmtime.Canonical(timeStamp).Format(TimeFormat))))
	return hasher.Sum(nil)

}

func BlockIDHasher(m tmproto.CanonicalBlockID) []byte {

	hasher := ihash.New()
	hasher.Write(m.GetHash())
	hasher.Write(CPSetHeaderHasher(m.GetPartSetHeader()))

	r := hasher.Sum(nil)

	return r
}

func CPSetHeaderHasher(canPartSetHeader tmproto.CanonicalPartSetHeader) []byte {
	//The organising principle is for hashes we put it directly into the hasher,
	// for other formats we hash them seperately first

	totalb := make([]byte, 8)
	encoding_binary.BigEndian.PutUint64(totalb, uint64(canPartSetHeader.Total))
	hasherForTotal := ihash.New()
	hasherForTotal.Write(totalb)

	hasher := ihash.New()
	hasher.Write(hasherForTotal.Sum(nil))
	hasher.Write(canPartSetHeader.Hash)

	r := hasher.Sum(nil)

	return r

}
