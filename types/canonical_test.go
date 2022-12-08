package types

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/proto/tendermint/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
)

func TestCanonicalizeBlockID(t *testing.T) {
	randhash := pedersen.RandFeltBytes(32)
	block1 := tmproto.BlockID{Hash: randhash,
		PartSetHeader: tmproto.PartSetHeader{Total: 5, Hash: randhash}}
	block2 := tmproto.BlockID{Hash: randhash,
		PartSetHeader: tmproto.PartSetHeader{Total: 10, Hash: randhash}}
	cblock1 := tmproto.CanonicalBlockID{Hash: randhash,
		PartSetHeader: tmproto.CanonicalPartSetHeader{Total: 5, Hash: randhash}}
	cblock2 := tmproto.CanonicalBlockID{Hash: randhash,
		PartSetHeader: tmproto.CanonicalPartSetHeader{Total: 10, Hash: randhash}}

	tests := []struct {
		name string
		args tmproto.BlockID
		want *tmproto.CanonicalBlockID
	}{
		{"first", block1, &cblock1},
		{"second", block2, &cblock2},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonicalizeBlockID(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CanonicalizeBlockID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCairoCanonicalVoteNoTime(t *testing.T) {
	// load input and expected from json file
	filename := "../test_inputs/hash_test_can_vote.json"
	data_out := utils.LoadJsonHCVNTA(filename)

	// create CanonicalVote instance
	cbid_hash := utils.ByteRounder(32)(big.NewInt(data_out.CanonicalBlockIDHash).Bytes())
	psh_hash := utils.ByteRounder(32)(big.NewInt(data_out.PSHHash).Bytes())
	PSH := types.CanonicalPartSetHeader{Total: data_out.PSHTotal, Hash: psh_hash}
	blockid := types.CanonicalBlockID{Hash: cbid_hash, PartSetHeader: PSH}
	time0 := time.Unix(0, data_out.Time)
	canonicalVote := tmproto.CanonicalVote{
		Type:      types.SignedMsgType(data_out.Type),
		Height:    data_out.Height,
		Round:     data_out.Round,
		BlockID:   &blockid,
		Timestamp: time0,
		ChainID:   data_out.ChainID,
	}
	// run input from json file through HashCanonicalVoteNoTime

	resHash := big.NewInt(0).SetBytes(HashCanonicalVoteNoTime(canonicalVote))

	// compare output to expected

	require.Equal(t, data_out.Expected, resHash.String(), "TestCase %s failed: hashes don't match: %s != %s", data_out.Name, data_out.Expected, resHash.String())
	fmt.Println("resHash: ", resHash)
}

func TestCairoHashTime(t *testing.T) {
	// load input and expected from json file
	filename := "../test_inputs/hash_test_time.json"
	data_out := utils.LoadJsonHashTime(filename)

	// create Time instance
	time0 := time.Unix(0, data_out.Time)
	// run input from json file through HashTime

	resHash := big.NewInt(0).SetBytes(HashTime(time0))

	// compare output to expected

	require.Equal(t, data_out.Expected, resHash.String(), "TestCase %s failed: hashes don't match: %s != %s", data_out.Name, data_out.Expected, resHash.String())
	fmt.Println("resHash: ", resHash)
}

func TestCairoCPSHHasher(t *testing.T) {
	// load input and expected from json file
	filename := "../test_inputs/hash_test_cpsh.json"
	data_out := utils.LoadJsonCPSetHeader(filename)

	// create CPSH instance
	cpsh_hash := utils.ByteRounder(32)(big.NewInt(data_out.Hash).Bytes())

	cpsh := types.CanonicalPartSetHeader{Total: data_out.Total, Hash: cpsh_hash}

	// run input from json file through MerkleRootHashVals

	resHash := big.NewInt(0).SetBytes(HashCPSetHeader(cpsh))

	// compare output to expected

	require.Equal(t, data_out.Expected, resHash.String(), "TestCase %s failed: hashes don't match: %s != %s", data_out.Name, data_out.Expected, resHash.String())
	fmt.Println("resHash: ", resHash)
}
