package privval

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/crypto/stark"
	cryptoproto "github.com/tendermint/tendermint/proto/tendermint/crypto"
	privproto "github.com/tendermint/tendermint/proto/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/types"
)

var stamp = time.Date(2019, 10, 13, 16, 14, 44, 0, time.UTC)

func exampleVote() *types.Vote {
	return &types.Vote{
		Type:             tmproto.SignedMsgType(1),
		Height:           3,
		Round:            2,
		Timestamp:        stamp,
		BlockID:          types.BlockID{Hash: crypto.Checksum128([]byte("blockID_hash")), PartSetHeader: types.PartSetHeader{Total: 1000000, Hash: crypto.Checksum128([]byte("blockID_part_set_header_hash"))}},
		ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
		ValidatorIndex:   56789,
	}
}

func exampleProposal() *types.Proposal {

	return &types.Proposal{
		Type:      tmproto.SignedMsgType(1),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		POLRound:  2,
		Signature: []byte("it's a signature"),
		BlockID: types.BlockID{
			Hash: crypto.Checksum128([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  crypto.Checksum128([]byte("blockID_part_set_header_hash")),
			},
		},
	}
}

func TestPrivvalVectors(t *testing.T) {
	pk := stark.GenPrivKeyFromSecret([]byte("it's a secret")).PubKey()
	ppk, err := encoding.PubKeyToProto(pk)
	require.NoError(t, err)

	// Generate a simple vote
	vote := exampleVote()
	votepb := vote.ToProto()

	// Generate a simple proposal
	proposal := exampleProposal()
	proposalpb := proposal.ToProto()

	// Create a Reuseable remote error
	remoteError := &privproto.RemoteSignerError{Code: 1, Description: "it's a error"}

	testCases := []struct {
		testName string
		msg      proto.Message
		expBytes string
	}{
		{"ping request", &privproto.PingRequest{}, "3a00"},
		{"ping response", &privproto.PingResponse{}, "4200"},
		{"pubKey request", &privproto.PubKeyRequest{}, "0a00"},
		{"pubKey response", &privproto.PubKeyResponse{PubKey: ppk, Error: nil}, "12440a42224001e243d6f9853e954e7fd63f230825cbb56ab346e340fa3cd5b3a3243757195705503daf5991a99425511c4fdc778a2cbbc6f6db8cafd591d9c3fe7949226b4a"},
		{"pubKey response with error", &privproto.PubKeyResponse{PubKey: cryptoproto.PublicKey{}, Error: remoteError}, "12140a0012100801120c697427732061206572726f72"},
		{"Vote Request", &privproto.SignVoteRequest{Vote: votepb}, "1a8e010a8b01080210031802224a0a2003e7a58a7e2d9ebe51da3a5fe11c4795b464e84d9b29e293efa41331bae8e094122608c0843d122001031d61b8e12a45dfdda50a056cbd5281f024574a304d4bb53baa7a3bfa55992a0608f49a8ded053220043138d42edf17664fdea6079761873fd57d7cedc3685abdf9fe9384f1e1520f38d5bb034a09657874656e73696f6e"},
		{"Vote Response", &privproto.SignedVoteResponse{Vote: *votepb, Error: nil}, "228e010a8b01080210031802224a0a2003e7a58a7e2d9ebe51da3a5fe11c4795b464e84d9b29e293efa41331bae8e094122608c0843d122001031d61b8e12a45dfdda50a056cbd5281f024574a304d4bb53baa7a3bfa55992a0608f49a8ded053220043138d42edf17664fdea6079761873fd57d7cedc3685abdf9fe9384f1e1520f38d5bb034a09657874656e73696f6e"},
		{"Vote Response with error", &privproto.SignedVoteResponse{Vote: tmproto.Vote{}, Error: remoteError}, "22250a11220212002a0b088092b8c398feffffff0112100801120c697427732061206572726f72"},
		{"Proposal Request", &privproto.SignProposalRequest{Proposal: proposalpb}, "2a700a6e08011003180220022a4a0a2003e7a58a7e2d9ebe51da3a5fe11c4795b464e84d9b29e293efa41331bae8e094122608c0843d122001031d61b8e12a45dfdda50a056cbd5281f024574a304d4bb53baa7a3bfa5599320608f49a8ded053a10697427732061207369676e6174757265"},
		{"Proposal Response", &privproto.SignedProposalResponse{Proposal: *proposalpb, Error: nil}, "32700a6e08011003180220022a4a0a2003e7a58a7e2d9ebe51da3a5fe11c4795b464e84d9b29e293efa41331bae8e094122608c0843d122001031d61b8e12a45dfdda50a056cbd5281f024574a304d4bb53baa7a3bfa5599320608f49a8ded053a10697427732061207369676e6174757265"},
		{"Proposal Response with error", &privproto.SignedProposalResponse{Proposal: tmproto.Proposal{}, Error: remoteError}, "32250a112a021200320b088092b8c398feffffff0112100801120c697427732061206572726f72"},
	}

	for _, tc := range testCases {
		tc := tc

		pm := mustWrapMsg(tc.msg)
		bz, err := pm.Marshal()
		require.NoError(t, err, tc.testName)

		require.Equal(t, tc.expBytes, hex.EncodeToString(bz), tc.testName)
	}
}
