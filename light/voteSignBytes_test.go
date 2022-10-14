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
	abstractions "github.com/tendermint/tendermint/crypto/abstractions"
	"github.com/tendermint/tendermint/crypto/stark"
	"github.com/tendermint/tendermint/light"

	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/crypto/weierstrass"
	tmtypes "github.com/tendermint/tendermint/types"
)

func TestVerifyAdjecent(t *testing.T) {

	trustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-10-14T11:06:35.413940948Z","last_block_id":{"hash":"01F491396B02D56397E056A39D7EF263DF45254F89C40B17B28CFB6FB7CCFD2E","parts":{"total":1,"hash":"0740C1781E703EF4BE74626BB920F569D5CE37200C2DC91226D0D0099E52AC09"}},"last_commit_hash":"02E02E5672C11EC3A039ECFA9943FA2BB343A4A152BFFDA19DAA10F37B7541CD","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","next_validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275"},"commit":{"height":"2","round":0,"block_id":{"hash":"01F94F4D5BCFBE0DDAB054594502152C52360597273194CEE5ADB579311EC87B","parts":{"total":1,"hash":"03B603B1874C195AE40D080CAEB3104142A0FCD9BE3E7A8FFC405353E408889E"}},"signatures":[{"block_id_flag":2,"validator_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","timestamp":"2022-10-14T11:06:40.929141572Z","signature":"BCKoIfq1Fxpa/I2De9PhoN592+Bj3zVSKHMiUTD6mEAFbWctuH8wILbzsT4l4SGVsI4VxbGWL1fT/1Oek/qZCA=="}]}},"canonical":true}`
	untrustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-10-14T11:06:47.517886346Z","last_block_id":{"hash":"01F94F4D5BCFBE0DDAB054594502152C52360597273194CEE5ADB579311EC87B","parts":{"total":1,"hash":"03B603B1874C195AE40D080CAEB3104142A0FCD9BE3E7A8FFC405353E408889E"}},"last_commit_hash":"04F15F70594118DBC13E8BB1193068B6DFFBF1AD26139C59A4416FD7F22D8E6E","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","next_validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275"},"commit":{"height":"3","round":0,"block_id":{"hash":"01CA28D76EC5D4D638F612BEE925C5804793F551E499F525244F042A38D424E8","parts":{"total":1,"hash":"001FDC137CEA02A840FBCC7C22DACC9BAD77859FF2BBE5C5756FD0D0FC4B889B"}},"signatures":[{"block_id_flag":2,"validator_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","timestamp":"2022-10-14T11:06:53.288348623Z","signature":"BERs118Hd4uHTIOTIiiwF+xgRzZZlYK1a4wuJzxAVUYEc9IiBpmZZ64/BU/jfrIfZCBbCgJYg6lhQpHJgnuTpg=="}]}},"canonical":true}`
	validatorsString := `{"block_height":"3","validators":[{"address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","pub_key":{"type":"tendermint/PubKeyStark","value":"BCSyZuiwaiVNC0tMTPQrXGoZQpYImwdyV3K88ltKu7EC2JFryijF/Td9JaXiEVWqpwsSwllhhrY8lJDBmwt2BA=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`

	var trustedLightB tmtypes.LightBlock
	json.Unmarshal([]byte(trustedLightBString), &trustedLightB)

	var untrustedLightB tmtypes.LightBlock
	json.Unmarshal([]byte(untrustedLightBString), &untrustedLightB)

	var validators tmtypes.ValidatorSet
	json.Unmarshal([]byte(validatorsString), &validators)

	maxDrift := time.Duration(999999999)
	trustingPeriod := maxDrift
	timeNow := time.Unix(0, 1665745607517887346)

	err := light.VerifyAdjacent(trustedLightB.SignedHeader, untrustedLightB.SignedHeader, &validators, trustingPeriod, timeNow, maxDrift)
	fmt.Println(err)
	return
}

func TestFormatLightBlock(t *testing.T) {
	trustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-10-14T11:06:35.413940948Z","last_block_id":{"hash":"01F491396B02D56397E056A39D7EF263DF45254F89C40B17B28CFB6FB7CCFD2E","parts":{"total":1,"hash":"0740C1781E703EF4BE74626BB920F569D5CE37200C2DC91226D0D0099E52AC09"}},"last_commit_hash":"02E02E5672C11EC3A039ECFA9943FA2BB343A4A152BFFDA19DAA10F37B7541CD","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","next_validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275"},"commit":{"height":"2","round":0,"block_id":{"hash":"01F94F4D5BCFBE0DDAB054594502152C52360597273194CEE5ADB579311EC87B","parts":{"total":1,"hash":"03B603B1874C195AE40D080CAEB3104142A0FCD9BE3E7A8FFC405353E408889E"}},"signatures":[{"block_id_flag":2,"validator_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","timestamp":"2022-10-14T11:06:40.929141572Z","signature":"BCKoIfq1Fxpa/I2De9PhoN592+Bj3zVSKHMiUTD6mEAFbWctuH8wILbzsT4l4SGVsI4VxbGWL1fT/1Oek/qZCA=="}]}},"canonical":true}`
	untrustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-10-14T11:06:47.517886346Z","last_block_id":{"hash":"01F94F4D5BCFBE0DDAB054594502152C52360597273194CEE5ADB579311EC87B","parts":{"total":1,"hash":"03B603B1874C195AE40D080CAEB3104142A0FCD9BE3E7A8FFC405353E408889E"}},"last_commit_hash":"04F15F70594118DBC13E8BB1193068B6DFFBF1AD26139C59A4416FD7F22D8E6E","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","next_validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275"},"commit":{"height":"3","round":0,"block_id":{"hash":"01CA28D76EC5D4D638F612BEE925C5804793F551E499F525244F042A38D424E8","parts":{"total":1,"hash":"001FDC137CEA02A840FBCC7C22DACC9BAD77859FF2BBE5C5756FD0D0FC4B889B"}},"signatures":[{"block_id_flag":2,"validator_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","timestamp":"2022-10-14T11:06:53.288348623Z","signature":"BERs118Hd4uHTIOTIiiwF+xgRzZZlYK1a4wuJzxAVUYEc9IiBpmZZ64/BU/jfrIfZCBbCgJYg6lhQpHJgnuTpg=="}]}},"canonical":true}`
	validatorsString := `{"block_height":"3","validators":[{"address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","pub_key":{"type":"tendermint/PubKeyStark","value":"BCSyZuiwaiVNC0tMTPQrXGoZQpYImwdyV3K88ltKu7EC2JFryijF/Td9JaXiEVWqpwsSwllhhrY8lJDBmwt2BA=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`

	var trustedLightB tmtypes.LightBlock
	json.Unmarshal([]byte(trustedLightBString), &trustedLightB)

	trustedtimeb := make([]byte, 8)
	binary.BigEndian.PutUint64(trustedtimeb, uint64(trustedLightB.SignedHeader.Header.Time.UnixNano()))
	trustedtimeNano := big.NewInt(0).SetBytes(trustedtimeb)

	chainIDchunks := utils.Split(abstractions.ByteRounder([]byte(trustedLightB.SignedHeader.Header.ChainID)), 8)
	chainIDlen := len(chainIDchunks)

	fmt.Println(`let (local chain_id_ptr: felt*) =alloc()`)

	for i := 0; i < chainIDlen; i++ {
		fmt.Println(`	assert chain_id_ptr[`, i, `]=`, fmt.Sprint(big.NewInt(0).SetBytes(chainIDchunks[i])))
	}

	fmt.Println(`	let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = `, chainIDlen, `)`)

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
		app_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.AppHash)) + `,
		last_results_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.LastResultsHash)) + `,
		evidence_hash =` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.EvidenceHash)) + `, 
		proposer_address =  ` + fmt.Sprint(big.NewInt(0).SetBytes(trustedLightB.SignedHeader.Header.ProposerAddress)) + `
		)`)

	timeb2 := make([]byte, 8)
	binary.BigEndian.PutUint64(timeb2, uint64(trustedLightB.Commit.Signatures[0].Timestamp.UnixNano()))

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
		app_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.AppHash)) + `,
		last_results_hash = ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.LastResultsHash)) + `,
		evidence_hash =` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.EvidenceHash)) + `, 
		proposer_address =  ` + fmt.Sprint(big.NewInt(0).SetBytes(untrustedLightB.SignedHeader.Header.ProposerAddress)) + `
		)`)

	timeb4 := make([]byte, 8)

	binary.BigEndian.PutUint64(timeb4, uint64(untrustedLightB.Commit.Signatures[0].Timestamp.UnixNano()))

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
		let untrusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)
		`)

	var validators tmtypes.ValidatorSet
	json.Unmarshal([]byte(validatorsString), &validators)

	// pubkey := validators.Validators[0].PubKey
	// fmt.Println("PublicKey x coord:", big.NewInt(0).SetBytes(pubkey.Bytes()[:32]))
	// fmt.Println("PublicKey y coord:", big.NewInt(0).SetBytes(pubkey.Bytes()[32:]))

	// fmt.Println("valaddress in hex:", pubkey.Address())
	// fmt.Println("validator address:", big.NewInt(0).SetBytes(pubkey.Address().Bytes()))

	// sigToVerify := untrustedLightB.Commit.Signatures[0].Signature
	// fmt.Println("sigToVerify_r", big.NewInt(0).SetBytes(sigToVerify[:32]))
	// fmt.Println("sigToVerify_s", big.NewInt(0).SetBytes(sigToVerify[32:]))

	fmt.Println(`
		# create validator array
		let (local ValidatorData_pointer0: ValidatorData*) =alloc()
		let public_key0: PublicKeyData  = PublicKeyData( ecdsa = `, big.NewInt(0).SetBytes(validators.Validators[0].PubKey.Bytes()[:32]), `)
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
		
		return()
	end	`)

}

func TestVoteSignBytes2(t *testing.T) {

	trustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-10-12T11:08:35.768622043Z","last_block_id":{"hash":"01C61DE54A56CD0D37B7DCF84B97A5F40E3BA22C30D9AA1DD84D66EB0EEBC416","parts":{"total":1,"hash":"0360B92DEDE55F8F02463AF262A8F839DE668DC8E1AB90092FBF5EACA8F7ABA9"}},"last_commit_hash":"0701258106A46658D773232E7EBA607C7B25A0FE6668826155BFB9FD8A1B8B5D","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"03BA4084376F83640C38D8297F25CC0BC6CD0C05F147C3A4016CB36DD5F1B224","next_validators_hash":"03BA4084376F83640C38D8297F25CC0BC6CD0C05F147C3A4016CB36DD5F1B224","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"00958FD35B52A4A9239B3E3BF3FB425012B6642F99E36DD173D66B33CC0FB1CF"},"commit":{"height":"2","round":0,"block_id":{"hash":"01B5722AFB68747A0D6AB0EEFE7731549A1CDF60879F6F0DB4D07E1C5E51D6C4","parts":{"total":1,"hash":"02224A8285228804AFE2734CADE45C3C22E3328FEFF507C43DFDAF698433E3A5"}},"signatures":[{"block_id_flag":2,"validator_address":"00958FD35B52A4A9239B3E3BF3FB425012B6642F99E36DD173D66B33CC0FB1CF","timestamp":"2022-10-12T11:08:45.210794311Z","signature":"B0p4EpANS5++q/YR+zPoJMe2Phw/5N7hcueBk8u/rUcAUtmEbVCDm7yidzK1o1X8D2ICaXINStyrLa/KMZi9hg=="}]}},"canonical":false}`
	// untrustedLightBString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-10-14T11:06:47.517886346Z","last_block_id":{"hash":"01F94F4D5BCFBE0DDAB054594502152C52360597273194CEE5ADB579311EC87B","parts":{"total":1,"hash":"03B603B1874C195AE40D080CAEB3104142A0FCD9BE3E7A8FFC405353E408889E"}},"last_commit_hash":"04F15F70594118DBC13E8BB1193068B6DFFBF1AD26139C59A4416FD7F22D8E6E","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","next_validators_hash":"052C9B411FF6CF27281D4528BE392356B299E1BB94E78ED9F64936DB602E9AE3","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275"},"commit":{"height":"3","round":0,"block_id":{"hash":"01CA28D76EC5D4D638F612BEE925C5804793F551E499F525244F042A38D424E8","parts":{"total":1,"hash":"001FDC137CEA02A840FBCC7C22DACC9BAD77859FF2BBE5C5756FD0D0FC4B889B"}},"signatures":[{"block_id_flag":2,"validator_address":"07505C4FCAD35561F9118A049D9C97CB01C2F60D845BDBE25639BB1706EA0275","timestamp":"2022-10-14T11:06:53.288348623Z","signature":"BERs118Hd4uHTIOTIiiwF+xgRzZZlYK1a4wuJzxAVUYEc9IiBpmZZ64/BU/jfrIfZCBbCgJYg6lhQpHJgnuTpg=="}]}},"canonical":true}`
	validatorsString := `{"block_height":"2","validators":[{"address":"00958FD35B52A4A9239B3E3BF3FB425012B6642F99E36DD173D66B33CC0FB1CF","pub_key":{"type":"tendermint/PubKeyStark","value":"A9qOd0kGozxFqN8BWQUGIRvAwZO7EDLAcyOL51jtTQQEM+g7ZhIcMSDgJXPM9T89aYYwQ8/nGFPyS9iTpd3EvA=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`

	var trustedLightB tmtypes.LightBlock
	json.Unmarshal([]byte(trustedLightBString), &trustedLightB)

	// var untrustedLightB tmtypes.LightBlock
	// json.Unmarshal([]byte(untrustedLightBString), &untrustedLightB)

	var validators tmtypes.ValidatorSet
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

	chainIDfelt1 := big.NewInt(0).SetBytes(abstractions.ByteRounder([]byte("test-chain-IrF74Y"))[:8])
	chainIDfelt2 := big.NewInt(0).SetBytes(abstractions.ByteRounder([]byte("test-chain-IrF74Y"))[8:16])
	chainIDfelt3 := big.NewInt(0).SetBytes(abstractions.ByteRounder([]byte("test-chain-IrF74Y"))[16:])

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

func TestPubKey1(t *testing.T) {
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

func TestPubKey2(t *testing.T) {

	x, _ := big.NewInt(0).SetString("1136674174985150922078555914567443880539140333523709298787895514313564632578", 10)
	y1, _ := big.NewInt(0).SetString("846885536432209687901461023988246066195122457552151769524987280290562469016", 10)
	y2, _ := big.NewInt(0).SetString("1183542427150969392626018984893467106583918766494481729382281203507622641472", 10)

	// pubkey1 := stark.PublicKey{weierstrass.Stark(), x, y1}
	// pubkey2 := stark.PublicKey{weierstrass.Stark(), x, y2}
	fmt.Println(weierstrass.Stark().IsOnCurve(x, y1))
	fmt.Println(weierstrass.Stark().IsOnCurve(x, y2))

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
