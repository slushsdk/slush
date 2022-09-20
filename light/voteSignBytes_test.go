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
	var trustedLightB tmtypes.LightBlock
	trustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-09-19T17:00:00.681940869Z","last_block_id":{"hash":"03B34509B2FA4FDEB1115BD80168207A365F272A6D2BD5989355A0CE499CC473","parts":{"total":1,"hash":"01427CF58F58645B400484D01662AA4BD689E2BB129328AD5F2F236F6393F3FD"}},"last_commit_hash":"058A532E3E2F73093426460D77C59F5D4011198B6D8A2E698201E921A94A8733","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"0405CC204253A271CB6D12930BA7C3173808AD541E14E4C436B85FD29671B5EF","next_validators_hash":"0405CC204253A271CB6D12930BA7C3173808AD541E14E4C436B85FD29671B5EF","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65"},"commit":{"height":"2","round":0,"block_id":{"hash":"049505D4D6BF0D2A0586886DBB50D76955A9108D97832C5BAB7C5B22958C4053","parts":{"total":1,"hash":"01DBEDC3C6A0B3A8AC0A3585DD12131A241DD8F50439D1B033B56B04D4945F1E"}},"signatures":[{"block_id_flag":2,"validator_address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65","timestamp":"2022-09-19T17:00:04.136627792Z","signature":"A32u0tqGz6txMHy6RH78U8fHK3pZa9JUOr6OOllmhG0GMv0BNcoX2cJDBC+y4VQBdvwBpUxQlmvAhfipI5SNZQ=="}]}},"canonical":true}`
	json.Unmarshal([]byte(trustedLightBString), &trustedLightB)

	trustedtimeb := make([]byte, 8)
	binary.BigEndian.PutUint64(trustedtimeb, uint64(trustedLightB.SignedHeader.Header.Time.UnixNano()))
	trustedtimeNano := big.NewInt(0).SetBytes(trustedtimeb)

	chainIDchunks := utils.Split([]byte(trustedLightB.SignedHeader.Header.ChainID), 8)
	chainIDlen := len(chainIDchunks)

	fmt.Println(`let (local chain_id_ptr: felt*) =alloc()`)

	for i := 0; i < chainIDlen; i++ {
		fmt.Println(`assert chain_id_ptr[`, i, `]=`, fmt.Sprint(big.NewInt(0).SetBytes(chainIDchunks[i])))
	}

	fmt.Println(`let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = `, chainIDlen, `)`)

	fmt.Println(`
		# create the header
		let header1_trusted: LightHeaderData = LightHeaderData(
		version = ConsensusData(block = ` + fmt.Sprint(trustedLightB.SignedHeader.Header.Version.Block) + `, app= ` + fmt.Sprint(trustedLightB.SignedHeader.Header.Version.App) + `),
		chain_id = chain_id1, #this is a placeholder value
		height = ` + fmt.Sprint(trustedLightB.SignedHeader.Header.Height) + `,
		time = TimestampData(nanos =` + fmt.Sprint(trustedtimeNano) + `),  
		last_block_id = BlockIDData(hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.LastBlockID.Hash)) + `, 
		part_set_header = PartSetHeaderData(total = ` + fmt.Sprint((trustedLightB.SignedHeader.Header.LastBlockID.PartSetHeader.Total)) + `,
		 hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.LastBlockID.PartSetHeader.Hash)) + `)),
		last_commit_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.LastCommitHash)) + `,
		data_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.DataHash)) + `,
		validators_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.ValidatorsHash)) + `,
		next_validators_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.NextValidatorsHash)) + `,
		consensus_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.ConsensusHash)) + `,
		app_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.ConsensusHash)) + `,
		last_results_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.LastResultsHash)) + `,
		evidence_hash =` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.EvidenceHash)) + `, 
		proposer_address =  ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.ProposerAddress)) + `
		)`)

	timeb2 := make([]byte, 8)
	binary.BigEndian.PutUint64(timeb2, uint64(trustedLightB.SignedHeader.Header.Time.UnixNano()))

	fmt.Println(`
	# create commit
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

    let signature_data_trusted: SignatureData = SignatureData(signature_r =`, fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.Commit.Signatures[0].Signature[:32])), `, signature_s =`, fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.Commit.Signatures[0].Signature[32:])), `)

    local commitsig_Absent_trusted : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = `, fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.Commit.Signatures[0].ValidatorAddress)), `,
    timestamp = TimestampData(nanos= `, fmt.Sprint(big.NewInt(0).SetBytes(timeb2)), `), signature= signature_data_trusted)

    let (local commitsig1_pointer_trusted: CommitSigData*) =alloc()   
    assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted
    let commitsig1_array_trusted = CommitSigDataArray(array = commitsig1_pointer_trusted, len = 1)

    let commit1_trusted: CommitData = CommitData(height = `, fmt.Sprint((trustedLightB.Commit.Height)), `, 
    round = `, fmt.Sprint(trustedLightB.Commit.Round), `, 
    block_id= BlockIDData(
            hash= `, fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.Commit.BlockID.Hash)), `,
            part_set_header = PartSetHeaderData(total = `, fmt.Sprint((trustedLightB.Commit.BlockID.PartSetHeader.Total)), `, hash=`, fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.Commit.BlockID.PartSetHeader.Hash)), `)),
    signatures = commitsig1_array_trusted
    )
    
    # create the header from these two
    let trusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)
	`)

	var untrustedLightB tmtypes.LightBlock
	untrustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-09-19T17:00:09.004032497Z","last_block_id":{"hash":"049505D4D6BF0D2A0586886DBB50D76955A9108D97832C5BAB7C5B22958C4053","parts":{"total":1,"hash":"01DBEDC3C6A0B3A8AC0A3585DD12131A241DD8F50439D1B033B56B04D4945F1E"}},"last_commit_hash":"048019782DACD568CF088CB170F03B31BE84124F58E1ADE0AAD0192880900794","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"0405CC204253A271CB6D12930BA7C3173808AD541E14E4C436B85FD29671B5EF","next_validators_hash":"0405CC204253A271CB6D12930BA7C3173808AD541E14E4C436B85FD29671B5EF","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65"},"commit":{"height":"3","round":0,"block_id":{"hash":"079E6C61ABAA973E7EBA92CFF4F53C12601EA59F2C2A3EFBADF551DA42C22DC9","parts":{"total":1,"hash":"040DD14383B7712236557176BB37A8B21BFC448FEB86DB6A59A3681883583960"}},"signatures":[{"block_id_flag":2,"validator_address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65","timestamp":"2022-09-19T17:00:12.767354909Z","signature":"B9U5PCGpW8RIdb/w8krMx7ktF3+vxrU7obu96ypG0EUDdWYxtIbEOflB3zp2GGIMs3YjoFwd0qZYxbfPh1HnmQ=="}]}},"canonical":true}`
	json.Unmarshal([]byte(untrustedLightBString), &untrustedLightB)
	// fmt.Println(untrustedLightB)

	untrustedtimeb := make([]byte, 8)
	binary.BigEndian.PutUint64(untrustedtimeb, uint64(untrustedLightB.SignedHeader.Header.Time.UnixNano()))
	untrustedtimeNano := big.NewInt(0).SetBytes(untrustedtimeb)

	fmt.Println(`
		# create the header
		let header1_trusted: LightHeaderData = LightHeaderData(
		version = ConsensusData(block = ` + fmt.Sprint(untrustedLightB.SignedHeader.Header.Version.Block) + `, app= ` + fmt.Sprint(untrustedLightB.SignedHeader.Header.Version.App) + `),
		chain_id = chain_id1, #this is a placeholder value
		height = ` + fmt.Sprint(untrustedLightB.SignedHeader.Header.Height) + `,
		time = TimestampData(nanos =` + fmt.Sprint(untrustedtimeNano) + `),  
		last_block_id = BlockIDData(hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.LastBlockID.Hash)) + `, 
		part_set_header = PartSetHeaderData(total = ` + fmt.Sprint((untrustedLightB.SignedHeader.Header.LastBlockID.PartSetHeader.Total)) + `,
		 hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.LastBlockID.PartSetHeader.Hash)) + `)),
		last_commit_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.LastCommitHash)) + `,
		data_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.DataHash)) + `,
		validators_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.ValidatorsHash)) + `,
		next_validators_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.NextValidatorsHash)) + `,
		consensus_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.ConsensusHash)) + `,
		app_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.ConsensusHash)) + `,
		last_results_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.LastResultsHash)) + `,
		evidence_hash =` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.EvidenceHash)) + `, 
		proposer_address =  ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.ProposerAddress)) + `
		)`)

	timeb4 := make([]byte, 8)
	binary.BigEndian.PutUint64(timeb4, uint64(untrustedLightB.SignedHeader.Header.Time.UnixNano()))

	fmt.Println(`
		# create commit
		let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)
	
		let signature_data_trusted: SignatureData = SignatureData(signature_r =`, fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.Commit.Signatures[0].Signature[:32])), `, signature_s =`, fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.Commit.Signatures[0].Signature[32:])), `)
	
		local commitsig_Absent_trusted : CommitSigData = CommitSigData(
		block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = `, fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.Commit.Signatures[0].ValidatorAddress)), `,
		timestamp = TimestampData(nanos= `, fmt.Sprint(big.NewInt(0).SetBytes(timeb4)), `), signature= signature_data_trusted)
	
		let (local commitsig1_pointer_trusted: CommitSigData*) =alloc()   
		assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted
		let commitsig1_array_trusted = CommitSigDataArray(array = commitsig1_pointer_trusted, len = 1)
	
		let commit1_trusted: CommitData = CommitData(height = `, fmt.Sprint((untrustedLightB.Commit.Height)), `, 
		round = `, fmt.Sprint(untrustedLightB.Commit.Round), `, 
		block_id= BlockIDData(
				hash= `, fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.Commit.BlockID.Hash)), `,
				part_set_header = PartSetHeaderData(total = `, fmt.Sprint((untrustedLightB.Commit.BlockID.PartSetHeader.Total)), `, hash=`, fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.Commit.BlockID.PartSetHeader.Hash)), `)),
		signatures = commitsig1_array_trusted
		)
		
		# create the header from these two
		let trusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)
		`)

	var validators tmtypes.ValidatorSet
	validatorsString := `{"block_height":"2","validators":[{"address":"0095539E78DE6938CE9EE6044CDA74C91999CAEDCC82FC4FA3D1006CC6FC0528","pub_key":{"type":"tendermint/PubKeyStark","value":"AeoNSTzqpGGyucRJnB3tadvJpSuXX8pyaP6ZM/liK+EALFbuBbuuotawTYZ3al8Ql7vZj4ehJSIDb9hfadmqlw=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`
	json.Unmarshal([]byte(validatorsString), &validators)

	pubkey := validators.Validators[0].PubKey
	fmt.Println("PublicKey x coord:", big.NewInt(0).SetBytes(pubkey.Bytes()[:32]))
	fmt.Println("PublicKey y coord:", big.NewInt(0).SetBytes(pubkey.Bytes()[32:]))

	fmt.Println("valaddress in hex:", pubkey.Address())
	fmt.Println("validator address:", big.NewInt(0).SetBytes(pubkey.Address().Bytes()))

	sigToVerify := untrustedLightB.Commit.Signatures[0].Signature
	fmt.Println("sigToVerify_r", big.NewInt(0).SetBytes(sigToVerify[:32]))
	fmt.Println("sigToVerify_s", big.NewInt(0).SetBytes(sigToVerify[32:]))

	fmt.Println(`# create validator array
    let (local ValidatorData_pointer0: ValidatorData*) =alloc()
    let public_key0: PublicKeyData  = PublicKeyData(ed25519= 0, secp256k1 = 1, sr25519 = 2, ecdsa = `, big.NewInt(0).SetBytes(validators.Validators[0].PubKey.Bytes()[:32]), `)
    let validator_data0: ValidatorData =  ValidatorData(Address = `, big.NewInt(0).SetBytes(validators.Validators[0].Address), `,
    pub_key = public_key0, voting_power= `, validators.Validators[0].VotingPower, `, proposer_priority = `, validators.Validators[0].ProposerPriority, `)
    assert ValidatorData_pointer0[0] = validator_data0
                                                        
    let validator_array0: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer0, len = 1)
    let validator_set0: ValidatorSetData = ValidatorSetData(validators = validator_array0, proposer = validator_data0, total_voting_power =10 )
    let currentTime2 = DurationData(nanos = `, untrustedtimeNano.Add(untrustedtimeNano, big.NewInt(1000)), `)
    let maxClockDrift= DurationData(nanos = 10)
    let trustingPeriod = DurationData(nanos = 99999999999999999999)
	
	verifyAdjacent(trustedHeader= trusted_header, untrustedHeader= untrusted_header, untrustedVals=validator_set0,
		trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift) 
	`)

}

func TestVoteSignBytes2(t *testing.T) {
	var trustedLightB tmtypes.LightBlock
	trustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-09-19T17:00:00.681940869Z","last_block_id":{"hash":"03B34509B2FA4FDEB1115BD80168207A365F272A6D2BD5989355A0CE499CC473","parts":{"total":1,"hash":"01427CF58F58645B400484D01662AA4BD689E2BB129328AD5F2F236F6393F3FD"}},"last_commit_hash":"058A532E3E2F73093426460D77C59F5D4011198B6D8A2E698201E921A94A8733","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"0405CC204253A271CB6D12930BA7C3173808AD541E14E4C436B85FD29671B5EF","next_validators_hash":"0405CC204253A271CB6D12930BA7C3173808AD541E14E4C436B85FD29671B5EF","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65"},"commit":{"height":"2","round":0,"block_id":{"hash":"049505D4D6BF0D2A0586886DBB50D76955A9108D97832C5BAB7C5B22958C4053","parts":{"total":1,"hash":"01DBEDC3C6A0B3A8AC0A3585DD12131A241DD8F50439D1B033B56B04D4945F1E"}},"signatures":[{"block_id_flag":2,"validator_address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65","timestamp":"2022-09-19T17:00:04.136627792Z","signature":"A32u0tqGz6txMHy6RH78U8fHK3pZa9JUOr6OOllmhG0GMv0BNcoX2cJDBC+y4VQBdvwBpUxQlmvAhfipI5SNZQ=="}]}},"canonical":true}`
	json.Unmarshal([]byte(trustedLightBString), &trustedLightB)

	// var untrustedLightB tmtypes.LightBlock
	// untrustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-09-08T16:11:04.763248526Z","last_block_id":{"hash":"0649AB0076E5077AF132102CC0AC6B0D4EAE791C02F6DD50A74E7A2BC9334E53","parts":{"total":1,"hash":"01651E1B0AFA095DEE7095F09D5ACE92DF8D63D0505321C7F4B87FD6B62829ED"}},"last_commit_hash":"0448A7650B3CCEB5B4141FD41625A5AEDAE8BB2C9B576D63860F836814E927BD","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"04AFB1DB90B5623523ED49FB710AC8893175CBD5118F516AE6282D448A86D955","next_validators_hash":"04AFB1DB90B5623523ED49FB710AC8893175CBD5118F516AE6282D448A86D955","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"0095539E78DE6938CE9EE6044CDA74C91999CAEDCC82FC4FA3D1006CC6FC0528"},"commit":{"height":"3","round":0,"block_id":{"hash":"06680F8FD44101C8FBE570AB6993F2FFC4E684A98BF5409D77CDAE63B90B7402","parts":{"total":1,"hash":"003AD81CE057151B288B255D242D1BAD75B85C65283336F2556E45C604037CC8"}},"signatures":[{"block_id_flag":2,"validator_address":"0095539E78DE6938CE9EE6044CDA74C91999CAEDCC82FC4FA3D1006CC6FC0528","timestamp":"2022-09-08T16:11:08.681766435Z","signature":"AFsri2XkA/F2hYNNpa/HmIAJgGU0i4qYY9wimmhNZ5UG4F9kPNne6berMKP2IJ/Ey7b9y5tN4jzumYYOZ2saIg=="}]}},"canonical":true}`
	// json.Unmarshal([]byte(untrustedLightBString), &untrustedLightB)

	var validators tmtypes.ValidatorSet
	validatorsString := `{"block_height":"2","validators":[{"address":"0664C7D58CFE259D8C576AB0A088FED380EC88D57D5CC758D02842FAD419CF65","pub_key":{"type":"tendermint/PubKeyStark","value":"BJUfdY/5dW+lhBzdi1xyOKd/yguH5rcEjQtrgI6TiPgA5HxvQzlUitMnLXRACOAjdk5ZAT6cjsxuFdF/g5IAYw=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`
	json.Unmarshal([]byte(validatorsString), &validators)

	partSHHash := trustedLightB.Commit.BlockID.PartSetHeader.Hash
	blockIDHash := trustedLightB.Commit.BlockID.Hash
	valAdd := validators.Validators[0].Address

	partSH := tmtypes.PartSetHeader{Total: 1, Hash: partSHHash}

	blockID := tmtypes.BlockID{Hash: blockIDHash, PartSetHeader: partSH}

	sigafter := []byte{0x00} // we don't need this.
	time := trustedLightB.Commit.Signatures[0].Timestamp
	commitsig := tmtypes.CommitSig{BlockIDFlag: 2, ValidatorAddress: valAdd, Timestamp: time, Signature: sigafter}
	sigs := []tmtypes.CommitSig{commitsig}

	height := trustedLightB.Commit.Height
	round := trustedLightB.Commit.Round

	commit := tmtypes.Commit{Height: height, Round: round, BlockID: blockID, Signatures: sigs}

	chainID := trustedLightB.SignedHeader.ChainID
	voteSB := commit.VoteSignBytes(chainID, 0)

	sigToVerify := trustedLightB.Commit.Signatures[0].Signature

	pubkey := validators.Validators[0].PubKey

	pass := pubkey.VerifySignature(voteSB, sigToVerify)
	// fmt.Println("Results: ")
	// fmt.Println(pass, pubkey, voteSB)
	require.True(t, pass)
}

//note: this test works with a specific data. The underlying methods have changed (but not the data), so it does not work anymore.
func TestVoteSignBytes1(t *testing.T) {
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
	fmt.Println("newsig", newSig)
	fmt.Println("read signature", sigToVerify)
	fmt.Println("newSig_r", big.NewInt(0).SetBytes(newSig[:32]))
	fmt.Println("newSig_s", big.NewInt(0).SetBytes(newSig[32:]))

	chainIDfelt1 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[:8])
	chainIDfelt2 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[8:16])
	chainIDfelt3 := big.NewInt(0).SetBytes(ihash.ByteRounder([]byte("test-chain-IrF74Y"))[16:])

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
