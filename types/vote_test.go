package types

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/stark"
	tmtime "github.com/tendermint/tendermint/libs/time"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

const (
	//nolint: lll
	preCommitTestStr = `Vote{56789:06FF842DF41F 12345/2 Precommit 000EDB91B7E0 000000000000 0 @ 2017-12-25T03:00:01.234Z}`
	//nolint: lll
	preVoteTestStr = `Vote{56789:06FF842DF41F 12345/2 Prevote 000EDB91B7E0 000000000000 0 @ 2017-12-25T03:00:01.234Z}`
)

var (
	// nolint: lll
	nilVoteTestStr                = fmt.Sprintf(`Vote{56789:06FF842DF41F 12345/2 Precommit %s 000000000000 0 @ 2017-12-25T03:00:01.234Z}`, nilVoteStr)
	formatNonEmptyVoteExtensionFn = func(voteExtensionLength int) string {
		// nolint: lll
		return fmt.Sprintf(`Vote{56789:06FF842DF41F 12345/2 Precommit 000EDB91B7E0 000000000000 %d @ 2017-12-25T03:00:01.234Z}`, voteExtensionLength)
	}
)

func examplePrevote(t *testing.T) *Vote {
	t.Helper()
	return exampleVote(t, byte(tmproto.PrevoteType))
}

func examplePrecommit(t testing.TB) *Vote {
	t.Helper()
	vote := exampleVote(t, byte(tmproto.PrecommitType))
	vote.ExtensionSignature = []byte("signature")
	return vote
}

func exampleVote(tb testing.TB, t byte) *Vote {
	tb.Helper()
	var stamp, err = time.Parse(TimeFormat, "2017-12-25T03:00:01.234Z")
	require.NoError(tb, err)

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
	vote := examplePrecommit(t)
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
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x7, 0xff, 0x80, 0xfc, 0x3f, 0x9c, 0x7, 0xb3, 0xaf, 0xdf, 0x92, 0x58, 0xe2, 0xd2, 0x5d, 0xc8, 0x2c, 0x4, 0xb8, 0x80, 0x47, 0xa9, 0x4f, 0x43, 0x19, 0xb2, 0x91, 0xe5, 0xc4, 0x22, 0xfc, 0xe7}},
		// containing vote extension
		5: {
			"test_chain_id", &Vote{
				Height:    1,
				Round:     1,
				Extension: []byte("extension"),
			},
			[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa1, 0xb2, 0x3, 0xeb, 0x3d, 0x1a, 0x0, 0x0, 0x7, 0xff, 0x80, 0xfc, 0x3f, 0x9c, 0x7, 0xb3, 0xaf, 0xdf, 0x92, 0x58, 0xe2, 0xd2, 0x5d, 0xc8, 0x2c, 0x4, 0xb8, 0x80, 0x47, 0xa9, 0x4f, 0x43, 0x19, 0xb2, 0x91, 0xe5, 0xc4, 0x22, 0xfc, 0xe7}},
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privVal := NewMockPV()
	pubkey, err := privVal.GetPubKey(ctx)
	require.NoError(t, err)

	vote := examplePrecommit(t)
	v := vote.ToProto()
	signBytes := VoteSignBytes("test_chain_id", v)

	// sign it
	err = privVal.SignVote(ctx, "test_chain_id", v)
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

// TestVoteExtension tests that the vote verification behaves correctly in each case
// of vote extension being set on the vote.
func TestVoteExtension(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testCases := []struct {
		name             string
		extension        []byte
		includeSignature bool
		expectError      bool
	}{
		{
			name:             "all fields present",
			extension:        []byte("extension"),
			includeSignature: true,
			expectError:      false,
		},
		{
			name:             "no extension signature",
			extension:        []byte("extension"),
			includeSignature: false,
			expectError:      true,
		},
		{
			name:             "empty extension",
			includeSignature: true,
			expectError:      false,
		},
		{
			name:             "no extension and no signature",
			includeSignature: false,
			expectError:      true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			height, round := int64(1), int32(0)
			privVal := NewMockPV()
			pk, err := privVal.GetPubKey(ctx)
			require.NoError(t, err)
			blk := Block{}
			ps, err := blk.MakePartSet(BlockPartSizeBytes)
			require.NoError(t, err)
			vote := &Vote{
				ValidatorAddress: pk.Address(),
				ValidatorIndex:   0,
				Height:           height,
				Round:            round,
				Timestamp:        tmtime.Now(),
				Type:             tmproto.PrecommitType,
				BlockID:          BlockID{blk.Hash(), ps.Header()},
			}

			v := vote.ToProto()
			err = privVal.SignVote(ctx, "test_chain_id", v)
			require.NoError(t, err)
			vote.Signature = v.Signature
			if tc.includeSignature {
				vote.ExtensionSignature = v.ExtensionSignature
			}
			err = vote.VerifyExtension("test_chain_id", pk)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privVal := NewMockPV()
	pubkey, err := privVal.GetPubKey(ctx)
	require.NoError(t, err)

	vote := examplePrevote(t)
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
	testcases := map[string]struct {
		vote           *Vote
		expectedResult string
	}{
		"pre-commit": {
			vote:           examplePrecommit(t),
			expectedResult: preCommitTestStr,
		},
		"pre-vote": {
			vote:           examplePrevote(t),
			expectedResult: preVoteTestStr,
		},
		"absent vote": {
			expectedResult: absentVoteStr,
		},
		"nil vote": {
			vote: func() *Vote {
				v := examplePrecommit(t)
				v.BlockID.Hash = nil
				return v
			}(),
			expectedResult: nilVoteTestStr,
		},
		"non-empty vote extension": {
			vote: func() *Vote {
				v := examplePrecommit(t)
				v.Extension = []byte{1, 2}
				return v
			}(),
			expectedResult: formatNonEmptyVoteExtensionFn(2),
		},
	}

	for name, tc := range testcases {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.expectedResult, tc.vote.String())
		})
	}
}

func signVote(ctx context.Context, t *testing.T, pv PrivValidator, chainID string, vote *Vote) {
	t.Helper()

	v := vote.ToProto()
	require.NoError(t, pv.SignVote(ctx, chainID, v))
	vote.Signature = v.Signature
	vote.ExtensionSignature = v.ExtensionSignature
}

func TestValidVotes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	privVal := NewMockPV()

	testCases := []struct {
		name         string
		vote         *Vote
		malleateVote func(*Vote)
	}{
		{"good prevote", examplePrevote(t), func(v *Vote) {}},
		{"good precommit without vote extension", examplePrecommit(t), func(v *Vote) { v.Extension = nil }},
		{"good precommit with vote extension", examplePrecommit(t), func(v *Vote) { v.Extension = []byte("extension") }},
	}
	for _, tc := range testCases {
		signVote(ctx, t, privVal, "test_chain_id", tc.vote)
		tc.malleateVote(tc.vote)
		require.NoError(t, tc.vote.ValidateBasic(), "ValidateBasic for %s", tc.name)
		require.NoError(t, tc.vote.EnsureExtension(), "EnsureExtension for %s", tc.name)
	}
}

func TestInvalidVotes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	privVal := NewMockPV()

	testCases := []struct {
		name         string
		malleateVote func(*Vote)
	}{
		{"negative height", func(v *Vote) { v.Height = -1 }},
		{"negative round", func(v *Vote) { v.Round = -1 }},
		{"invalid block ID", func(v *Vote) { v.BlockID = BlockID{[]byte{1, 2, 3}, PartSetHeader{111, []byte("blockparts")}} }},
		{"invalid address", func(v *Vote) { v.ValidatorAddress = make([]byte, 1) }},
		{"invalid validator index", func(v *Vote) { v.ValidatorIndex = -1 }},
		{"invalid signature", func(v *Vote) { v.Signature = nil }},
		{"oversized signature", func(v *Vote) { v.Signature = make([]byte, MaxSignatureSize+1) }},
	}
	for _, tc := range testCases {
		prevote := examplePrevote(t)
		signVote(ctx, t, privVal, "test_chain_id", prevote)
		tc.malleateVote(prevote)
		require.Error(t, prevote.ValidateBasic(), "ValidateBasic for %s in invalid prevote", tc.name)
		require.NoError(t, prevote.EnsureExtension(), "EnsureExtension for %s in invalid prevote", tc.name)

		precommit := examplePrecommit(t)
		signVote(ctx, t, privVal, "test_chain_id", precommit)
		tc.malleateVote(precommit)
		require.Error(t, precommit.ValidateBasic(), "ValidateBasic for %s in invalid precommit", tc.name)
		require.NoError(t, precommit.EnsureExtension(), "EnsureExtension for %s in invalid precommit", tc.name)
	}
}

func TestInvalidPrevotes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	privVal := NewMockPV()

	testCases := []struct {
		name         string
		malleateVote func(*Vote)
	}{
		{"vote extension present", func(v *Vote) { v.Extension = []byte("extension") }},
		{"vote extension signature present", func(v *Vote) { v.ExtensionSignature = []byte("signature") }},
	}
	for _, tc := range testCases {
		prevote := examplePrevote(t)
		signVote(ctx, t, privVal, "test_chain_id", prevote)
		tc.malleateVote(prevote)
		require.Error(t, prevote.ValidateBasic(), "ValidateBasic for %s", tc.name)
		require.NoError(t, prevote.EnsureExtension(), "EnsureExtension for %s", tc.name)
	}
}

func TestInvalidPrecommitExtensions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	privVal := NewMockPV()

	testCases := []struct {
		name         string
		malleateVote func(*Vote)
	}{
		{"vote extension present without signature", func(v *Vote) {
			v.Extension = []byte("extension")
			v.ExtensionSignature = nil
		}},
		{"oversized vote extension signature", func(v *Vote) { v.ExtensionSignature = make([]byte, MaxSignatureSize+1) }},
	}
	for _, tc := range testCases {
		precommit := examplePrecommit(t)
		signVote(ctx, t, privVal, "test_chain_id", precommit)
		tc.malleateVote(precommit)
		// ValidateBasic ensures that vote extensions, if present, are well formed
		require.Error(t, precommit.ValidateBasic(), "ValidateBasic for %s", tc.name)
	}
}

func TestEnsureVoteExtension(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	privVal := NewMockPV()

	testCases := []struct {
		name         string
		malleateVote func(*Vote)
		expectError  bool
	}{
		{"vote extension signature absent", func(v *Vote) {
			v.Extension = nil
			v.ExtensionSignature = nil
		}, true},
		{"vote extension signature present", func(v *Vote) {
			v.ExtensionSignature = []byte("extension signature")
		}, false},
	}
	for _, tc := range testCases {
		precommit := examplePrecommit(t)
		signVote(ctx, t, privVal, "test_chain_id", precommit)
		tc.malleateVote(precommit)
		if tc.expectError {
			require.Error(t, precommit.EnsureExtension(), "EnsureExtension for %s", tc.name)
		} else {
			require.NoError(t, precommit.EnsureExtension(), "EnsureExtension for %s", tc.name)
		}
	}
}

func TestVoteProtobuf(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privVal := NewMockPV()
	vote := examplePrecommit(t)
	v := vote.ToProto()
	err := privVal.SignVote(ctx, "test_chain_id", v)
	vote.Signature = v.Signature
	require.NoError(t, err)

	testCases := []struct {
		msg                 string
		vote                *Vote
		convertsOk          bool
		passesValidateBasic bool
	}{
		{"success", vote, true, true},
		{"fail vote validate basic", &Vote{}, true, false},
	}
	for _, tc := range testCases {
		protoProposal := tc.vote.ToProto()

		v, err := VoteFromProto(protoProposal)
		if tc.convertsOk {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}

		err = v.ValidateBasic()
		if tc.passesValidateBasic {
			require.NoError(t, err)
			require.Equal(t, tc.vote, v, tc.msg)
		} else {
			require.Error(t, err)
		}
	}
}

var sink interface{}

func getSampleCommit(ctx context.Context, t testing.TB) *Commit {
	t.Helper()

	lastID := makeBlockIDRandom()
	voteSet, _, vals := randVoteSet(ctx, t, 2, 1, tmproto.PrecommitType, 10, 1)
	commit, err := makeExtCommit(ctx, lastID, 2, 1, voteSet, vals, time.Now())

	require.NoError(t, err)

	return commit.ToCommit()
}

func BenchmarkVoteSignBytes(b *testing.B) {
	protoVote := examplePrecommit(b).ToProto()

	b.ReportAllocs()
	b.ResetTimer()

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sampleCommit := getSampleCommit(ctx, b)

	b.ReportAllocs()
	b.ResetTimer()

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
