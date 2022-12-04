package types

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/stark"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

func examplePrevote() *Vote {
	return exampleVote(byte(tmproto.PrevoteType))
}

func examplePrecommit() *Vote {
	return exampleVote(byte(tmproto.PrecommitType))
}

func exampleVote(t byte) *Vote {
	var stamp, err = time.Parse(TimeFormat, "2017-12-25T03:00:01.234Z")
	if err != nil {
		panic(err)
	}

	return &Vote{
		Type:      tmproto.SignedMsgType(t),
		Height:    12345,
		Round:     2,
		Timestamp: stamp,
		BlockID: BlockID{
			Hash: crypto.Checksum128([]byte("blockID_hash")),
			PartSetHeader: PartSetHeader{
				Total: 1000000,
				Hash:  crypto.Checksum128([]byte("blockID_part_set_header_hash")),
			},
		},
		ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
		ValidatorIndex:   56789,
	}
}

func TestVoteSignable(t *testing.T) {
	vote := examplePrecommit()
	v := vote.ToProto()
	signBytes := VoteSignBytes("test_chain_id", v)
	pb := CanonicalizeVote("test_chain_id", v)
	timeb := make([]byte, 32)
	binary.BigEndian.PutUint64(timeb[24:32], uint64(v.GetTimestamp().UnixNano()))

	expected := append(timeb, HashCanonicalVoteNoTime(pb)...)
	// require.NoError(t, err)

	require.Equal(t, expected, signBytes, "Got unexpected sign bytes for Vote.")
}

func TestVoteSignBytesTestVectors(t *testing.T) {

	tests := []struct {
		chainID string
		vote    *Vote
		want    []byte
	}{
		0: {
			"", &Vote{},
			// NOTE: Height and Round are skipped here. This case needs to be considered while parsing.
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x6, 0xc2, 0x17, 0x7e, 0xcf, 0xcc, 0x37, 0x38, 0x80, 0x5e, 0x54, 0x0, 0xa2, 0x6b, 0x9, 0x1, 0x76, 0xf6, 0x7c, 0xe2, 0x48, 0x8b, 0x8c, 0x81, 0x4c, 0xa8, 0xff, 0x65, 0x16, 0xff, 0x26, 0x17}},
		// with proper (fixed size) height and round (PreCommit):
		1: {
			"", &Vote{Height: 1, Round: 1, Type: tmproto.PrecommitType},
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x0, 0xcb, 0x1f, 0x14, 0x7f, 0x5d, 0x55, 0xa0, 0x92, 0x84, 0xb6, 0xf, 0xfc, 0x9c, 0xcb, 0xf6, 0x46, 0xf0, 0x55, 0x2e, 0x66, 0x8b, 0xfa, 0xa, 0x3d, 0x74, 0xfc, 0x4a, 0x41, 0x6c, 0x2f, 0xcd}},
		// with proper (fixed size) height and round (PreVote):
		2: {
			"", &Vote{Height: 1, Round: 1, Type: tmproto.PrevoteType},
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x2, 0x7e, 0xbe, 0xa2, 0x8, 0x42, 0x7, 0xb0, 0x70, 0xce, 0xd9, 0x7d, 0x73, 0x5b, 0xc5, 0x4e, 0x55, 0x5c, 0xcf, 0x29, 0xdd, 0x70, 0x39, 0x4d, 0x94, 0xd7, 0x5c, 0x34, 0x79, 0xfb, 0x60, 0x98}},
		3: {
			"", &Vote{Height: 1, Round: 1},
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x3, 0xd2, 0x2b, 0xa3, 0x79, 0x94, 0xb2, 0x18, 0x60, 0x99, 0xf8, 0xf3, 0xef, 0x20, 0xb, 0xc8, 0xb1, 0xf1, 0x48, 0xa3, 0xa9, 0x23, 0x39, 0xa5, 0x2, 0xbd, 0xa6, 0xdc, 0x20, 0x39, 0x1b, 0xe}},
		// containing non-empty chain_id:
		4: {
			"test_chain_id", &Vote{Height: 1, Round: 1},
			[]byte{0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x4c, 0xac, 0xe, 0xf3, 0xc6, 0x91, 0x2c, 0x37, 0x52, 0xdf, 0x53, 0xb7, 0xbc, 0x68, 0xaf, 0x8d, 0x37, 0x21, 0xb9, 0x9d, 0x60, 0x26, 0xe, 0x41, 0x1, 0x74, 0x85, 0x49, 0xb2, 0x38, 0xec, 0x86},
		},
	}
	for i, tc := range tests {
		v := tc.vote.ToProto()
		got := VoteSignBytes(tc.chainID, v)
		assert.Equal(t, len(tc.want), len(got), "test case #%v: got unexpected sign bytes length for Vote.", i)
		assert.Equal(t, tc.want, got, "test case #%v: got unexpected sign bytes for Vote.", i)
	}
}

func TestVoteProposalNotEq(t *testing.T) {
	cv := CanonicalizeVote("", &tmproto.Vote{Height: 1, Round: 1})
	p := CanonicalizeProposal("", &tmproto.Proposal{Height: 1, Round: 1})
	vb, err := proto.Marshal(&cv)
	require.NoError(t, err)
	pb, err := proto.Marshal(&p)
	require.NoError(t, err)
	require.NotEqual(t, vb, pb)
}

func TestVoteVerifySignature(t *testing.T) {
	privVal := NewMockPV()
	pubkey, err := privVal.GetPubKey(context.Background())
	require.NoError(t, err)

	vote := examplePrecommit()
	v := vote.ToProto()
	signBytes := VoteSignBytes("test_chain_id", v)

	// sign it
	err = privVal.SignVote(context.Background(), "test_chain_id", v)
	require.NoError(t, err)

	// verify the same vote
	valid := pubkey.VerifySignature(VoteSignBytes("test_chain_id", v), v.Signature)
	require.True(t, valid)

	// serialize, deserialize and verify again....
	precommit := new(tmproto.Vote)
	bs, err := proto.Marshal(v)
	require.NoError(t, err)
	err = proto.Unmarshal(bs, precommit)
	require.NoError(t, err)

	// verify the transmitted vote
	newSignBytes := VoteSignBytes("test_chain_id", precommit)
	require.Equal(t, string(signBytes), string(newSignBytes))
	valid = pubkey.VerifySignature(newSignBytes, precommit.Signature)
	require.True(t, valid)
}

func TestIsVoteTypeValid(t *testing.T) {
	tc := []struct {
		name string
		in   tmproto.SignedMsgType
		out  bool
	}{
		{"Prevote", tmproto.PrevoteType, true},
		{"Precommit", tmproto.PrecommitType, true},
		{"InvalidType", tmproto.SignedMsgType(0x3), false},
	}

	for _, tt := range tc {
		tt := tt
		t.Run(tt.name, func(st *testing.T) {
			if rs := IsVoteTypeValid(tt.in); rs != tt.out {
				t.Errorf("got unexpected Vote type. Expected:\n%v\nGot:\n%v", rs, tt.out)
			}
		})
	}
}

func TestVoteVerify(t *testing.T) {
	privVal := NewMockPV()
	pubkey, err := privVal.GetPubKey(context.Background())
	require.NoError(t, err)

	vote := examplePrevote()
	vote.ValidatorAddress = pubkey.Address()

	err = vote.Verify("test_chain_id", stark.GenPrivKey().PubKey())
	if assert.Error(t, err) {
		assert.Equal(t, ErrVoteInvalidValidatorAddress, err)
	}

	err = vote.Verify("test_chain_id", pubkey)
	if assert.Error(t, err) {
		assert.Equal(t, ErrVoteInvalidSignature, err)
	}
}

func TestVoteString(t *testing.T) {
	str := examplePrecommit().String()
	expected := `Vote{56789:6AF1F4111082 12345/02/SIGNED_MSG_TYPE_PRECOMMIT(Precommit) 8B01023386C3 000000000000 @ 2017-12-25T03:00:01.234Z}`
	if str != expected {
		t.Errorf("got unexpected string for Vote. Expected:\n%v\nGot:\n%v", expected, str)
	}

	str2 := examplePrevote().String()
	expected = `Vote{56789:6AF1F4111082 12345/02/SIGNED_MSG_TYPE_PREVOTE(Prevote) 8B01023386C3 000000000000 @ 2017-12-25T03:00:01.234Z}`
	if str2 != expected {
		t.Errorf("got unexpected string for Vote. Expected:\n%v\nGot:\n%v", expected, str2)
	}
}

func TestVoteValidateBasic(t *testing.T) {
	privVal := NewMockPV()

	testCases := []struct {
		testName     string
		malleateVote func(*Vote)
		expectErr    bool
	}{
		{"Good Vote", func(v *Vote) {}, false},
		{"Negative Height", func(v *Vote) { v.Height = -1 }, true},
		{"Negative Round", func(v *Vote) { v.Round = -1 }, true},
		{"Invalid BlockID", func(v *Vote) {
			v.BlockID = BlockID{[]byte{1, 2, 3}, PartSetHeader{111, []byte("blockparts")}}
		}, true},
		{"Invalid Address", func(v *Vote) { v.ValidatorAddress = make([]byte, 1) }, true},
		{"Invalid ValidatorIndex", func(v *Vote) { v.ValidatorIndex = -1 }, true},
		{"Invalid Signature", func(v *Vote) { v.Signature = nil }, true},
		{"Too big Signature", func(v *Vote) { v.Signature = make([]byte, MaxSignatureSize+1) }, true},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.testName, func(t *testing.T) {
			vote := examplePrecommit()
			v := vote.ToProto()
			err := privVal.SignVote(context.Background(), "test_chain_id", v)
			vote.Signature = v.Signature
			require.NoError(t, err)
			tc.malleateVote(vote)
			assert.Equal(t, tc.expectErr, vote.ValidateBasic() != nil, "Validate Basic had an unexpected result")
		})
	}
}

func TestVoteProtobuf(t *testing.T) {
	privVal := NewMockPV()
	vote := examplePrecommit()
	v := vote.ToProto()
	err := privVal.SignVote(context.Background(), "test_chain_id", v)
	vote.Signature = v.Signature
	require.NoError(t, err)

	testCases := []struct {
		msg     string
		v1      *Vote
		expPass bool
	}{
		{"success", vote, true},
		{"fail vote validate basic", &Vote{}, false},
		{"failure nil", nil, false},
	}
	for _, tc := range testCases {
		protoProposal := tc.v1.ToProto()

		v, err := VoteFromProto(protoProposal)
		if tc.expPass {
			require.NoError(t, err)
			require.Equal(t, tc.v1, v, tc.msg)
		} else {
			require.Error(t, err)
		}
	}
}

var sink interface{}

var protoVote *tmproto.Vote
var sampleCommit *Commit

func init() {
	protoVote = examplePrecommit().ToProto()

	lastID := makeBlockIDRandom()
	voteSet, _, vals := randVoteSet(2, 1, tmproto.PrecommitType, 10, 1)
	commit, err := makeCommit(lastID, 2, 1, voteSet, vals, time.Now())
	if err != nil {
		panic(err)
	}
	sampleCommit = commit
}

func BenchmarkVoteSignBytes(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sink = VoteSignBytes("test_chain_id", protoVote)
	}

	if sink == nil {
		b.Fatal("Benchmark did not run")
	}

	// Reset the sink.
	sink = (interface{})(nil)
}

func BenchmarkCommitVoteSignBytes(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for index := range sampleCommit.Signatures {
			sink = sampleCommit.VoteSignBytes("test_chain_id", int32(index))
		}
	}

	if sink == nil {
		b.Fatal("Benchmark did not run")
	}

	// Reset the sink.
	sink = (interface{})(nil)
}
