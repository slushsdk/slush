package light_test

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	ihash "github.com/tendermint/tendermint/crypto/abstractions"
	"github.com/tendermint/tendermint/crypto/stark"

	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/crypto/weierstrass"
	tmtypes "github.com/tendermint/tendermint/types"
)

func TestFormatLightBlock(t *testing.T) {
	var lightB tmtypes.LightBlock
	lightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-09-08T16:10:55.316448106Z","last_block_id":{"hash":"037984777B34EEC77D85858399DD022B361A765360921CADBE3EC468436C7F3C","parts":{"total":1,"hash":"0335E557006ED1963EC7016EBCDE8D571A42306DF8BAAF164B26F3BD2537B35A"}},"last_commit_hash":"01A85C969A45D5DC2D1D21C832C93B6EFA7E50E27FCE44EA674B3040EF8061A1","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"04AFB1DB90B5623523ED49FB710AC8893175CBD5118F516AE6282D448A86D955","next_validators_hash":"04AFB1DB90B5623523ED49FB710AC8893175CBD5118F516AE6282D448A86D955","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"0095539E78DE6938CE9EE6044CDA74C91999CAEDCC82FC4FA3D1006CC6FC0528"},"commit":{"height":"2","round":0,"block_id":{"hash":"0649AB0076E5077AF132102CC0AC6B0D4EAE791C02F6DD50A74E7A2BC9334E53","parts":{"total":1,"hash":"01651E1B0AFA095DEE7095F09D5ACE92DF8D63D0505321C7F4B87FD6B62829ED"}},"signatures":[{"block_id_flag":2,"validator_address":"0095539E78DE6938CE9EE6044CDA74C91999CAEDCC82FC4FA3D1006CC6FC0528","timestamp":"2022-09-08T16:10:59.364465136Z","signature":"AWBp8AkTRIALJ2UmG41GIiq9IO8e1rUnA98Lksle95AEqa/N/vtG0dKHI6ZNWFJLLgXUncHJvX6a6wLwkEUYFA=="}]}},"canonical":true}`
	json.Unmarshal([]byte(lightBString), &lightB)
	// fmt.Println(lightB)

	timeb := make([]byte, 8)
	binary.BigEndian.PutUint64(timeb, uint64(lightB.SignedHeader.Header.Time.UnixNano()))
	timeNano := big.NewInt(0).SetBytes(timeb)

	// chainIDchunks := utils.Split([]byte(lightB.SignedHeader.Header.ChainID), 8)
	// chainIDlen := len(chainIDchunks)

	fmt.Println(`
		
		let header1_trusted: LightHeaderData = LightHeaderData(
		version = ConsensusData(block = ` + fmt.Sprint(lightB.SignedHeader.Header.Version.Block) + `, app= ` + fmt.Sprint(lightB.SignedHeader.Header.Version.App) + `),
		chain_id = chain_id1, #this is a placeholder value
		height = ` + fmt.Sprint(lightB.SignedHeader.Header.Height) + `,
		time = TimestampData(nanos =` + fmt.Sprint(timeNano) + `),  
		last_block_id = BlockIDData(hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.LastBlockID.Hash)) + `, 
		part_set_header = PartSetHeaderData(total = ` + fmt.Sprint((lightB.SignedHeader.Header.LastBlockID.PartSetHeader.Total)) + `,
		 hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.LastBlockID.PartSetHeader.Hash)) + `)),
		last_commit_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.LastCommitHash)) + `,
		data_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.DataHash)) + `,
		validators_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.ValidatorsHash)) + `,
		next_validators_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.NextValidatorsHash)) + `,
		consensus_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.ConsensusHash)) + `,
		app_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.ConsensusHash)) + `,
		last_results_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.LastResultsHash)) + `,
		evidence_hash =` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.EvidenceHash)) + `, 
		proposer_address =  ` + fmt.Sprint(big.NewInt(0).SetBytes(lightB.SignedHeader.Header.ProposerAddress)) + `
		)`)

	var res3 []byte
	json.Unmarshal([]byte("\"AeoNSTzqpGGyucRJnB3tadvJpSuXX8pyaP6ZM/liK+EALFbuBbuuotawTYZ3al8Ql7vZj4ehJSIDb9hfadmqlw==\""), &res3)
	pubkey := stark.UnmarshalCompressedStark(weierstrass.Stark(), res3)
	fmt.Println("PublicKey x coord:", big.NewInt(0).SetBytes(pubkey.MarshalCompressedStark()[:32]))
	fmt.Println("PublicKey y coord:", big.NewInt(0).SetBytes(pubkey.MarshalCompressedStark()[32:]))

	// partSHHash, _ := hex.DecodeString("4BF25C4CE11F475F1180EAB799482F6BC9B016FBB9E0ABC19055BCA09769B300")
	// blockIDHash, _ := hex.DecodeString("02FC66FA6F1B6C864B002603CC258887195C4CC5C959DC5BF69158FA0FC86149")
	fmt.Println("valaddress in hex:", pubkey.MarshalCompressedStark().Address())
	valAdd, _ := hex.DecodeString("0095539E78DE6938CE9EE6044CDA74C91999CAEDCC82FC4FA3D1006CC6FC0528")
	fmt.Println("validator address:", big.NewInt(0).SetBytes(valAdd))

	// partSH := tmtypes.PartSetHeader{Total: 1, Hash: partSHHash}

	// blockID := tmtypes.BlockID{Hash: blockIDHash, PartSetHeader: partSH}

	// var sigafter []byte
	// json.Unmarshal([]byte("\"BOvtqdiGyNpUDvhXDaK3REuUvxtlSvGtdJ1+TZPouBIBgbUBHsEr61/fvvsSNtCQeJsFlZ494FI13FD8b7NPkg==\""), &sigafter)
	// commitsig := tmtypes.CommitSig{BlockIDFlag: 2, ValidatorAddress: valAdd, Timestamp: time.Date(2022, time.Month(9), 01, 14, 52, 21, 324707716, time.UTC), Signature: sigafter}
	// sigs := []tmtypes.CommitSig{commitsig}
	// fmt.Println("sig_r", big.NewInt(0).SetBytes(sigafter[:32]))
	// fmt.Println("sig_s", big.NewInt(0).SetBytes(sigafter[32:]))

	// commit := tmtypes.Commit{Height: 2, Round: 0, BlockID: blockID, Signatures: sigs}

	// fmt.Println("Commit: ")
	// fmt.Println(commit)
	// voteSB := commit.VoteSignBytes("test-chain-IrF74Y", 0)

	var sigToVerify []byte
	json.Unmarshal([]byte("\"AWBp8AkTRIALJ2UmG41GIiq9IO8e1rUnA98Lksle95AEqa/N/vtG0dKHI6ZNWFJLLgXUncHJvX6a6wLwkEUYFA==\""), &sigToVerify)
	fmt.Println("sigToVerify_r", big.NewInt(0).SetBytes(sigToVerify[:32]))
	fmt.Println("sigToVerify_s", big.NewInt(0).SetBytes(sigToVerify[32:]))

	var sigToVerify2 []byte
	json.Unmarshal([]byte("\"AEwnA/FUa6C7j4b+gxU66LsrxAegc9UeAgX59fenCwYBxBqImLdwCQK7ULB98Z4XUermQLkhVUNm+14MxMbCHg==\""), &sigToVerify2)
	fmt.Println("sigToVerify2_r", big.NewInt(0).SetBytes(sigToVerify2[:32]))
	fmt.Println("sigToVerify2_s", big.NewInt(0).SetBytes(sigToVerify2[32:]))

	// var res2 []byte
	// json.Unmarshal([]byte("\"AY/l4SrORfg5BDxH7cYI03BbV1fXpkDy9E7cxWSv6xoDn7Y0wOxU0s13iYRRr6AEOdyj2T45SFMIXe+hX9s+WA==\""), &res2)
	// pubkey2 := stark.UnmarshalCompressedStark(weierstrass.Stark(), res2)
	// // fmt.Println("Pubkey")
	// // fmt.Println(pubkey)
	// fmt.Println("pub_key_x", big.NewInt(0).SetBytes(res3[:32]))
	// fmt.Println("pub_key_x", big.NewInt(0).SetBytes(res3[32:]))

	// var res4 []byte
	// json.Unmarshal([]byte("\"B2vnWsuGyvuRLl9hPnEcaTDKWbdMk8VDec5vJJMkvyM=\""), &res4)
	// privkey := stark.PrivKey(res4)
	// fmt.Println("priv", big.NewInt(0).SetBytes(privkey[:32]))

	// fmt.Println("generated pubkey:", privkey.MakeFull().PublicKey)
	// newSig, _ := privkey.Sign(voteSB)
	// fmt.Println("newsig", newsig)
	// fmt.Println("read signature", sigToVerify)
	// fmt.Println("newSig_r", big.NewInt(0).SetBytes(newSig[:32]))
	// fmt.Println("newSig_s", big.NewInt(0).SetBytes(newSig[32:]))

	// chainIDfelt1 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[:8])
	// chainIDfelt2 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[8:16])
	// chainIDfelt3 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[16:])
	// // chainIDfelt4 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y")[24:32]))
	// // chainIDfelt5 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y")[32:]))
	// fmt.Println("chainIDFelts", chainIDfelt1, chainIDfelt2, chainIDfelt3)

	// pass := pubkey.MarshalCompressedStark().VerifySignature(voteSB, sigToVerify)
}

func TestVoteSignBytes(t *testing.T) {
	partSHHash, _ := hex.DecodeString("4BF25C4CE11F475F1180EAB799482F6BC9B016FBB9E0ABC19055BCA09769B300")
	blockIDHash, _ := hex.DecodeString("02FC66FA6F1B6C864B002603CC258887195C4CC5C959DC5BF69158FA0FC86149")
	valAdd, _ := hex.DecodeString("05FC9955EAEA18FED605223AB1E0E81BF80ED9A93701E95020F3D7E87CAEF46F")

	partSH := tmtypes.PartSetHeader{Total: 1, Hash: partSHHash}

	blockID := tmtypes.BlockID{Hash: blockIDHash, PartSetHeader: partSH}

	var sigafter []byte
	json.Unmarshal([]byte("\"BOvtqdiGyNpUDvhXDaK3REuUvxtlSvGtdJ1+TZPouBIBgbUBHsEr61/fvvsSNtCQeJsFlZ494FI13FD8b7NPkg==\""), &sigafter)
	commitsig := tmtypes.CommitSig{BlockIDFlag: 2, ValidatorAddress: valAdd, Timestamp: time.Date(2022, time.Month(9), 01, 14, 52, 21, 324707716, time.UTC), Signature: sigafter}
	sigs := []tmtypes.CommitSig{commitsig}
	fmt.Println("sig_r", big.NewInt(0).SetBytes(sigafter[:32]))
	fmt.Println("sig_s", big.NewInt(0).SetBytes(sigafter[32:]))

	commit := tmtypes.Commit{Height: 2, Round: 0, BlockID: blockID, Signatures: sigs}

	// fmt.Println("Commit: ")
	// fmt.Println(commit)
	voteSB := commit.VoteSignBytes("test-chain-IrF74Y", 0)

	var sigToVerify []byte
	json.Unmarshal([]byte("\"BKIueD6QxxhV+si8Gd1IapDYiaDYqzSrX0B9+G7+T18ExMPDfjKG7qu3l66qiLVEkOXXv6+yReP/g5QM/oeXpw==\""), &sigToVerify)
	fmt.Println("sigToVerify_r", big.NewInt(0).SetBytes(sigToVerify[:32]))
	fmt.Println("sigToVerify_s", big.NewInt(0).SetBytes(sigToVerify[32:]))

	var res3 []byte
	json.Unmarshal([]byte("\"AY/l4SrORfg5BDxH7cYI03BbV1fXpkDy9E7cxWSv6xoDn7Y0wOxU0s13iYRRr6AEOdyj2T45SFMIXe+hX9s+WA==\""), &res3)
	pubkey := stark.UnmarshalCompressedStark(weierstrass.Stark(), res3)
	// fmt.Println("Pubkey")
	// fmt.Println(pubkey)
	fmt.Println("pub_key_x", big.NewInt(0).SetBytes(res3[:32]))
	fmt.Println("pub_key_x", big.NewInt(0).SetBytes(res3[32:]))

	var res4 []byte
	json.Unmarshal([]byte("\"B2vnWsuGyvuRLl9hPnEcaTDKWbdMk8VDec5vJJMkvyM=\""), &res4)
	privkey := stark.PrivKey(res4)
	// fmt.Println("priv", big.NewInt(0).SetBytes(privkey[:32]))

	// fmt.Println("generated pubkey:", privkey.MakeFull().PublicKey)
	newSig, _ := privkey.Sign(voteSB)
	// fmt.Println("newsig", newsig)
	// fmt.Println("read signature", sigToVerify)
	fmt.Println("newSig_r", big.NewInt(0).SetBytes(newSig[:32]))
	fmt.Println("newSig_s", big.NewInt(0).SetBytes(newSig[32:]))

	chainIDfelt1 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[:8])
	chainIDfelt2 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[8:16])
	chainIDfelt3 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[16:])
	// chainIDfelt4 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y")[24:32]))
	// chainIDfelt5 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y")[32:]))
	fmt.Println("chainIDFelts", chainIDfelt1, chainIDfelt2, chainIDfelt3)

	pass := pubkey.MarshalCompressedStark().VerifySignature(voteSB, sigToVerify)
	// fmt.Println("Results: ")
	// fmt.Println(pass, pubkey, voteSB)
	require.True(t, pass)
}

func TestDeserialising(t *testing.T) {
	pv := stark.GenPrivKey()

	msg := []byte("hello world")
	sig, _ := pv.Sign(msg)
	sigJ, err := json.Marshal(sig)

	var msg2 []byte
	json.Unmarshal(sigJ, &msg2)

	fmt.Println(string(sigJ), err, msg2, sig)

	fmt.Println("Signature:")
	var res []byte
	err2 := json.Unmarshal([]byte("\"A32C5XtJxB+OOsq2AcrKYytbxkfrnnjDtucJpMNJ01EEjPSdWcxZVfg13txi/ua43e2+99z4kCILiJZBRCWUaA==\""), &res)
	// var sigJSON = string(res)

	fmt.Println(big.NewInt(0).SetBytes(res[:32]), big.NewInt(0).SetBytes(res[32:]), err2)

	fmt.Println("Pub key:")
	var res3 []byte
	err3 := json.Unmarshal([]byte("\"AGl5FHu8UbdTBlFNsKEWN6LWjBm4BLAT48ebp9mypQABkkchuGrRuDcasBUUo5Al2KoMDqL2LAHHhIWzSdhwHw==\""), &res3)
	// var sigJSON = string(res)
	x := big.NewInt(0).SetBytes(res3[:32])
	y := big.NewInt(0).SetBytes(res3[32:])
	pub := weierstrass.Marshal(weierstrass.Stark(), x, y)
	pubcomp := weierstrass.MarshalCompressed(weierstrass.Stark(), x, y)

	fmt.Println(x, pub, pubcomp, err3)

}

func TestPubKey(t *testing.T) {
	var res []byte
	json.Unmarshal([]byte("\"AeoNSTzqpGGyucRJnB3tadvJpSuXX8pyaP6ZM/liK+EALFbuBbuuotawTYZ3al8Ql7vZj4ehJSIDb9hfadmqlw==\""), &res)
	pubkey := stark.UnmarshalCompressedStark(weierstrass.Stark(), res)
	fmt.Println(pubkey.MarshalCompressedStark().Address())
	pubkey2 := stark.PubKey(res)
	fmt.Println(res)
	fmt.Println(pubkey2)
	fmt.Println(pubkey.MarshalCompressedStark())
	pubkey3 := crypto.PubKey(pubkey2)
	fmt.Println(pubkey3.Address())
}

func deserializeSig(sig []byte) (r *big.Int, s *big.Int, err error) {
	if len(sig) != 64 {
		return nil, nil, errors.New("Invalid signature length")
	}

	chunked := utils.Split(sig, 32)

	rBytes := chunked[0]
	sBytes := chunked[1]

	r = new(big.Int).SetBytes(rBytes)
	s = new(big.Int).SetBytes(sBytes)
	return r, s, nil
}
