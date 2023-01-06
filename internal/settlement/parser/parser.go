package parser

import (
	"fmt"
	"math/big"
	"reflect"
	"time"

	"github.com/tendermint/tendermint/crypto"

	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/crypto/weierstrass"
	"github.com/tendermint/tendermint/types"
	"github.com/tendermint/tendermint/version"
)

type blockIdFlagData struct {
	BlockIdFlag *big.Int `json:"BlockIDFlag"`
}

type timestampData struct {
	Nanos *big.Int `json:"nanos"`
}

type signatureData struct {
	SignatureR *big.Int `json:"signature_r"`
	SignatureS *big.Int `json:"signature_s"`
}

type commitSigData struct {
	BlockIdFlag      blockIdFlagData `json:"block_id_flag"`
	ValidatorAddress *big.Int        `json:"validator_address"`
	Timestamp        timestampData   `json:"timestamp"`
	Signature        signatureData   `json:"signature"`
}

type consensusData struct {
	Block *big.Int `json:"block"`
	App   *big.Int `json:"app"`
}

type partSetHeaderData struct {
	Total *big.Int `json:"total"`
	Hash  *big.Int `json:"hash"`
}

type blockIdData struct {
	Hash          *big.Int          `json:"hash"`
	PartSetHeader partSetHeaderData `json:"part_set_header"`
}

type headerArgs struct {
	ConsensusData      consensusData `json:"consensus_data"`
	Height             *big.Int      `json:"height"`
	Time               timestampData `json:"time"`
	LastBlockId        blockIdData   `json:"last_block_id"`
	LastCommitHash     *big.Int      `json:"last_commit_hash"`
	DataHash           *big.Int      `json:"data_hash"`
	ValidatorsHash     *big.Int      `json:"validators_hash"`
	NextValidatorsHash *big.Int      `json:"next_validators_hash"`
	ConsensusHash      *big.Int      `json:"consensus_hash"`
	AppHash            *big.Int      `json:"app_hash"`
	LastResultsHash    *big.Int      `json:"last_results_hash"`
	EvidenceHash       *big.Int      `json:"evidence_hash"`
	ProposerAddress    *big.Int      `json:"proposer_address"`
}

type commitArgs struct {
	Height  *big.Int    `json:"height"`
	Round   *big.Int    `json:"round"`
	BlockId blockIdData `json:"block_id"`
}

type signedHeaderArgs struct {
	Header headerArgs `json:"header"`
	Commit commitArgs `json:"commit"`
}

type publicKeyData struct {
	Ecdsa *big.Int `json:"ecdsa"`
}

type validatorData struct {
	Address          *big.Int      `json:"Address"`
	PubKey           publicKeyData `json:"pub_key"`
	VotingPower      *big.Int      `json:"voting_power"`
	ProposerPriority *big.Int      `json:"proposer_priority"`
}

type validatorSetArgs struct {
	Proposer         validatorData `json:"proposer"`
	TotalVotingPower *big.Int      `json:"total_voting_power"`
}

type durationData struct {
	Nanos *big.Int `json:"nanos"`
}

type verificationArgs struct {
	CurrentTime    durationData `json:"current_time"`
	MaxClockDrift  durationData `json:"max_clock_drift"`
	TrustingPeriod durationData `json:"trusting_period"`
}

type callData struct {
	ChainIdArray            []*big.Int       `json:"chain_id_array"`
	TrustedCommitSigArray   []commitSigData  `json:"trusted_commit_sig_array"`
	UntrustedCommitSigArray []commitSigData  `json:"untrusted_commit_sig_array"`
	ValidatorArray          []validatorData  `json:"validator_array"`
	Trusted                 signedHeaderArgs `json:"trusted"`
	Untrusted               signedHeaderArgs `json:"untrusted"`
	ValidatorSetArgs        validatorSetArgs `json:"validator_set_args"`
	VerificationArgs        verificationArgs `json:"verification_args"`
}

func formatPartSetHeader(partSetHeader types.PartSetHeader) partSetHeaderData {
	return partSetHeaderData{
		Total: big.NewInt(int64(partSetHeader.Total)),
		Hash:  big.NewInt(0).SetBytes(partSetHeader.Hash),
	}
}

func formatBlockId(blockId types.BlockID) blockIdData {
	return blockIdData{
		Hash:          big.NewInt(0).SetBytes(blockId.Hash),
		PartSetHeader: formatPartSetHeader(blockId.PartSetHeader),
	}
}

func formatConsensusData(consensus version.Consensus) consensusData {
	return consensusData{
		Block: big.NewInt(int64(consensus.Block)),
		App:   big.NewInt(int64(consensus.App)),
	}
}

func formatTimeStampData(timestamp time.Time) timestampData {
	return timestampData{
		Nanos: big.NewInt(timestamp.UnixNano()),
	}
}

func formatHeader(header *types.Header) headerArgs {
	return headerArgs{
		ConsensusData:      formatConsensusData(header.Version),
		Height:             big.NewInt(int64(header.Height)),
		Time:               formatTimeStampData(header.Time),
		LastBlockId:        formatBlockId(header.LastBlockID),
		LastCommitHash:     big.NewInt(0).SetBytes(header.LastCommitHash),
		DataHash:           big.NewInt(0).SetBytes(header.DataHash),
		ValidatorsHash:     big.NewInt(0).SetBytes(header.ValidatorsHash),
		NextValidatorsHash: big.NewInt(0).SetBytes(header.NextValidatorsHash),
		ConsensusHash:      big.NewInt(0).SetBytes(header.ConsensusHash),
		AppHash:            big.NewInt(0).SetBytes(header.AppHash),
		LastResultsHash:    big.NewInt(0).SetBytes(header.LastResultsHash),
		EvidenceHash:       big.NewInt(0).SetBytes(header.EvidenceHash),
		ProposerAddress:    big.NewInt(0).SetBytes(header.ProposerAddress),
	}
}

func formatCommit(commit *types.Commit) commitArgs {
	return commitArgs{
		Height:  big.NewInt(int64(commit.Height)),
		Round:   big.NewInt(int64(commit.Round)),
		BlockId: formatBlockId(commit.BlockID),
	}
}

func formatSignedHeader(signedHeader types.SignedHeader) signedHeaderArgs {
	return signedHeaderArgs{
		Header: formatHeader(signedHeader.Header),
		Commit: formatCommit(signedHeader.Commit),
	}
}

func formatPubKey(pubKey crypto.PubKey) publicKeyData {
	return publicKeyData{
		Ecdsa: big.NewInt(0).SetBytes(pubKey.Bytes()[:32]),
	}
}

func formatValidator(validator *types.Validator) validatorData {
	return validatorData{
		Address:          big.NewInt(0).SetBytes(validator.Address),
		PubKey:           formatPubKey(validator.PubKey),
		VotingPower:      big.NewInt(int64(validator.VotingPower)),
		ProposerPriority: big.NewInt(int64(validator.ProposerPriority)),
	}
}

func formatValidatorSet(validatorSet *types.ValidatorSet) validatorSetArgs {
	return validatorSetArgs{
		Proposer:         formatValidator(validatorSet.Proposer),
		TotalVotingPower: big.NewInt(int64(validatorSet.TotalVotingPower())),
	}
}

func formatDurationData(nanos *big.Int) durationData {
	return durationData{
		Nanos: nanos,
	}
}

func formatVerificationArgs(vc VerificationConfig) verificationArgs {
	return verificationArgs{
		CurrentTime:    formatDurationData(vc.CurrentTime),
		MaxClockDrift:  formatDurationData(vc.MaxClockDrift),
		TrustingPeriod: formatDurationData(vc.TrustingPeriod),
	}
}

func formatSignatureData(signature []byte) signatureData {
	if len(signature) != 64 {
		return signatureData{
			SignatureR: big.NewInt(0),
			SignatureS: big.NewInt(0),
		}
	}
	return signatureData{
		SignatureR: big.NewInt(0).SetBytes(signature[:32]),
		SignatureS: big.NewInt(0).SetBytes(signature[32:]),
	}
}

func formatBlockIdFlagData(blockIdFlag types.BlockIDFlag) blockIdFlagData {
	return blockIdFlagData{
		BlockIdFlag: big.NewInt(0).SetBytes([]byte{byte(blockIdFlag)}),
	}
}

func formatCommitSigArray(commitSigArray []types.CommitSig) []commitSigData {
	commitSigDataArray := make([]commitSigData, len(commitSigArray))
	for i, commitSig := range commitSigArray {
		commitSigDataArray[i] = commitSigData{
			BlockIdFlag:      formatBlockIdFlagData(commitSig.BlockIDFlag),
			ValidatorAddress: big.NewInt(0).SetBytes(commitSig.ValidatorAddress),
			Timestamp:        formatTimeStampData(commitSig.Timestamp),
			Signature:        formatSignatureData(commitSig.Signature),
		}
	}
	return commitSigDataArray
}

func formatValidatorArray(validators []*types.Validator) []validatorData {
	validatorArray := make([]validatorData, len(validators))
	for i, validator := range validators {
		validatorArray[i] = formatValidator(validator)
	}
	return validatorArray
}

func formatChainId(chainId string) []*big.Int {
	chainIDchunks := utils.Split(utils.ByteRounder(16)([]byte(chainId)), 16)

	chainIdArray := make([]*big.Int, len(chainIDchunks))

	for i, integer := range chainIDchunks {
		chainIdArray[i] = big.NewInt(0).SetBytes(integer)
	}
	return chainIdArray
}

type VerificationConfig struct {
	CurrentTime    *big.Int
	MaxClockDrift  *big.Int
	TrustingPeriod *big.Int
}

func formatCallData(trustedLB types.LightBlock, untrustedLB types.LightBlock, vc VerificationConfig) callData {
	return callData{
		ChainIdArray:            formatChainId(trustedLB.ChainID),
		TrustedCommitSigArray:   formatCommitSigArray(trustedLB.Commit.Signatures),
		UntrustedCommitSigArray: formatCommitSigArray(untrustedLB.Commit.Signatures),
		ValidatorArray:          formatValidatorArray(trustedLB.ValidatorSet.Validators),
		Trusted:                 formatSignedHeader(*trustedLB.SignedHeader),
		Untrusted:               formatSignedHeader(*untrustedLB.SignedHeader),
		ValidatorSetArgs:        formatValidatorSet(trustedLB.ValidatorSet),
		VerificationArgs:        formatVerificationArgs(vc),
	}
}

func serialize(input interface{}) (res []*big.Int, err error) {
	v := reflect.ValueOf(input)
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			var r []*big.Int
			if r, err = serialize(v.Field(i).Interface()); err != nil {
				return
			}
			res = append(res, r...)
		}
	case reflect.Slice:
		res = append(res, big.NewInt(int64(v.Len())))
		for i := 0; i < v.Len(); i++ {
			var r []*big.Int
			if r, err = serialize(v.Index(i).Interface()); err != nil {
				return
			}
			res = append(res, r...)
		}
	case reflect.Ptr:
		if reflect.TypeOf(input).String() == "*big.Int" {
			res = append(res, v.Interface().(*big.Int))
			return
		}
		fallthrough
	default:
		err = fmt.Errorf("expected input to be type of *big.Int or a slice, struct containing it, got '%T' instead", input)
	}
	return
}

func ParseInput(trustedLB types.LightBlock, untrustedLB types.LightBlock, vc VerificationConfig) (inputs []string, err error) {
	callData := formatCallData(trustedLB, untrustedLB, vc)
	bigInts, err := serialize(callData)
	if err != nil {
		return
	}
	inputs = make([]string, len(bigInts))
	for i, bigInt := range bigInts {
		if big.NewInt(0).Abs(bigInt).Cmp(weierstrass.Stark().Params().P) == 1 {
			err = fmt.Errorf("bigInt is out of range")
			return
		}

		if bigInt.Sign() == -1 {
			bigInt.Add(weierstrass.Stark().Params().P, bigInt)
		}
		inputs[i] = bigInt.String()
	}
	return
}
