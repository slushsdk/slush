package consensus

import (
	"fmt"
	"math/big"
	"time"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/internal/evidence"

	"github.com/tendermint/tendermint/crypto/pedersen"
	"github.com/tendermint/tendermint/crypto/utils"
	"github.com/tendermint/tendermint/types"
	"github.com/tendermint/tendermint/version"
)

type BlockIdFlagData struct {
	BlockIdFlag *big.Int `json:"BlockIDFlag"`
}

type TimestampData struct {
	Nanos *big.Int `json:"nanos"`
}

type SignatureData struct {
	SignatureR *big.Int `json:"signature_r"`
	SignatureS *big.Int `json:"signature_s"`
}

type CommitSigData struct {
	BlockIdFlag      BlockIdFlagData `json:"block_id_flag"`
	ValidatorAddress *big.Int        `json:"validator_address"`
	Timestamp        TimestampData   `json:"timestamp"`
	Signature        SignatureData   `json:"signature"`
}

type ConsensusData struct {
	Block *big.Int `json:"block"`
	App   *big.Int `json:"app"`
}

type PartSetHeaderData struct {
	Total *big.Int `json:"total"`
	Hash  *big.Int `json:"hash"`
}

type BlockIdData struct {
	Hash          *big.Int          `json:"hash"`
	PartSetHeader PartSetHeaderData `json:"part_set_header"`
}

type HeaderArgs struct {
	ConsensusData      ConsensusData `json:"consensus_data"`
	Height             *big.Int      `json:"height"`
	Time               TimestampData `json:"time"`
	LastBlockId        BlockIdData   `json:"last_block_id"`
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

type CommitArgs struct {
	Height  *big.Int    `json:"height"`
	Round   *big.Int    `json:"round"`
	BlockId BlockIdData `json:"block_id"`
}

type SignedHeaderArgs struct {
	Header HeaderArgs `json:"header"`
	Commit CommitArgs `json:"commit"`
}

type PublicKeyData struct {
	Ecdsa *big.Int `json:"ecdsa"`
}

type ValidatorData struct {
	Address          *big.Int      `json:"Address"`
	PubKey           PublicKeyData `json:"pub_key"`
	VotingPower      *big.Int      `json:"voting_power"`
	ProposerPriority *big.Int      `json:"proposer_priority"`
}

type ValidatorSetArgs struct {
	Proposer         ValidatorData `json:"proposer"`
	TotalVotingPower *big.Int      `json:"total_voting_power"`
}

type DurationData struct {
	Nanos *big.Int `json:"nanos"`
}

type VerificationArgs struct {
	CurrentTime    DurationData `json:"current_time"`
	MaxClockDrift  DurationData `json:"max_clock_drift"`
	TrustingPeriod DurationData `json:"trusting_period"`
}

type LightBlockArgs struct {
	SignedHeader SignedHeaderArgs `json:"signed_header"`
	ValidatorSet ValidatorSetArgs `json:"validator_set"`
}

type CallData struct {
	ChainIdArray            []*big.Int       `json:"chain_id_array"`
	TrustedCommitSigArray   []CommitSigData  `json:"trusted_commit_sig_array"`
	UntrustedCommitSigArray []CommitSigData  `json:"untrusted_commit_sig_array"`
	ValidatorArray          []ValidatorData  `json:"validator_array"`
	Trusted                 SignedHeaderArgs `json:"trusted"`
	Untrusted               SignedHeaderArgs `json:"untrusted"`
	ValidatorSetArgs        ValidatorSetArgs `json:"validator_set_args"`
	VerificationArgs        VerificationArgs `json:"verification_args"`
}

type External struct {
	VerifierAddress *big.Int `json:"address"`
	CallData        CallData `json:"calldata"`
}

type InvokeData struct {
	TrustedLightB   types.LightBlock
	UntrustedLightB types.LightBlock
	ValidatorSet    types.ValidatorSet
}

func formatPartSetHeader(partSetHeader types.PartSetHeader) PartSetHeaderData {
	return PartSetHeaderData{
		Total: big.NewInt(int64(partSetHeader.Total)),
		Hash:  big.NewInt(0).SetBytes(partSetHeader.Hash),
	}
}

func formatBlockId(blockId types.BlockID) BlockIdData {
	return BlockIdData{
		Hash:          big.NewInt(0).SetBytes(blockId.Hash),
		PartSetHeader: formatPartSetHeader(blockId.PartSetHeader),
	}
}

func formatConsensusData(consensus version.Consensus) ConsensusData {
	return ConsensusData{
		Block: big.NewInt(int64(consensus.Block)),
		App:   big.NewInt(int64(consensus.App)),
	}
}

func formatTimeStampData(timestamp time.Time) TimestampData {
	return TimestampData{
		Nanos: big.NewInt(timestamp.UnixNano()),
	}
}

func formatHeader(header *types.Header) HeaderArgs {
	return HeaderArgs{
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

func formatCommit(commit *types.Commit) CommitArgs {
	return CommitArgs{
		Height:  big.NewInt(int64(commit.Height)),
		Round:   big.NewInt(int64(commit.Round)),
		BlockId: formatBlockId(commit.BlockID),
	}
}

func FormatSignedHeader(signedHeader types.SignedHeader) SignedHeaderArgs {
	return SignedHeaderArgs{
		Header: formatHeader(signedHeader.Header),
		Commit: formatCommit(signedHeader.Commit),
	}
}

func formatPubKey(pubKey crypto.PubKey) PublicKeyData {
	return PublicKeyData{
		Ecdsa: big.NewInt(0).SetBytes(pubKey.Bytes()[:32]),
	}
}

func formatValidator(validator *types.Validator) ValidatorData {
	return ValidatorData{
		Address:          big.NewInt(0).SetBytes(validator.Address),
		PubKey:           formatPubKey(validator.PubKey),
		VotingPower:      big.NewInt(int64(validator.VotingPower)),
		ProposerPriority: big.NewInt(int64(validator.ProposerPriority)),
	}
}

func FormatValidatorSet(validatorSet *types.ValidatorSet) ValidatorSetArgs {
	return ValidatorSetArgs{
		Proposer:         formatValidator(validatorSet.Proposer),
		TotalVotingPower: big.NewInt(int64(validatorSet.TotalVotingPower())),
	}
}

func formatDurationData(nanos *big.Int) DurationData {
	return DurationData{
		Nanos: nanos,
	}
}

func FormatVerificationArgs(currentTime, maxClockDrift, trustingPeriod *big.Int) VerificationArgs {
	return VerificationArgs{
		CurrentTime:    formatDurationData(currentTime),
		MaxClockDrift:  formatDurationData(maxClockDrift),
		TrustingPeriod: formatDurationData(trustingPeriod),
	}
}

func formatSignatureData(signature []byte) SignatureData {
	return SignatureData{
		SignatureR: big.NewInt(0).SetBytes(signature[:32]),
		SignatureS: big.NewInt(0).SetBytes(signature[32:]),
	}
}

func formatBlockIdFlagData(blockIdFlag types.BlockIDFlag) BlockIdFlagData {
	return BlockIdFlagData{
		BlockIdFlag: big.NewInt(0).SetBytes([]byte{byte(blockIdFlag)}),
	}
}

func FormatCommitSigArray(commitSigArray []types.CommitSig) []CommitSigData {
	commitSigDataArray := make([]CommitSigData, len(commitSigArray))
	for i, commitSig := range commitSigArray {
		commitSigDataArray[i] = CommitSigData{
			BlockIdFlag:      formatBlockIdFlagData(commitSig.BlockIDFlag),
			ValidatorAddress: big.NewInt(0).SetBytes(commitSig.ValidatorAddress),
			Timestamp:        formatTimeStampData(commitSig.Timestamp),
			Signature:        formatSignatureData(commitSig.Signature),
		}
	}
	return commitSigDataArray
}

func FormatValidatorArray(validators []*types.Validator) []ValidatorData {
	validatorArray := make([]ValidatorData, len(validators))
	for i, validator := range validators {
		validatorArray[i] = formatValidator(validator)
	}
	return validatorArray
}

func formatChainId(chainId string) []*big.Int {
	chainIDchunks := utils.Split(pedersen.ByteRounder([]byte(chainId)), 8)

	chainIdArray := make([]*big.Int, len(chainIDchunks))

	for i, integer := range chainIDchunks {
		chainIdArray[i] = big.NewInt(0).SetBytes(integer)
	}
	return chainIdArray
}

func FormatCallData(trustedLightBlock types.LightBlock, untrustedLightBlock types.LightBlock, validatorSet *types.ValidatorSet, currentTime, maxClockDrift, trustingPeriod *big.Int) CallData {
	return CallData{
		ChainIdArray:            formatChainId(trustedLightBlock.ChainID),
		TrustedCommitSigArray:   FormatCommitSigArray(trustedLightBlock.Commit.Signatures),
		UntrustedCommitSigArray: FormatCommitSigArray(untrustedLightBlock.Commit.Signatures),
		ValidatorArray:          FormatValidatorArray(validatorSet.Validators),
		Trusted:                 FormatSignedHeader(*trustedLightBlock.SignedHeader),
		Untrusted:               FormatSignedHeader(*untrustedLightBlock.SignedHeader),
		ValidatorSetArgs:        FormatValidatorSet(validatorSet),
		VerificationArgs:        FormatVerificationArgs(currentTime, maxClockDrift, trustingPeriod),
	}
}

// we use this to push new block to settlment channel
func (cs *State) PushCommitToSettlment() error {
	trustedLightB, err := cs.getLightBlock(cs.Height - 3)
	if err != nil {
		return err
	}

	untrustedLightB, err := cs.getLightBlock(cs.Height - 2)
	if err != nil {
		return err
	}

	id := InvokeData{TrustedLightB: trustedLightB, UntrustedLightB: untrustedLightB, ValidatorSet: *trustedLightB.ValidatorSet}
	cs.SettlementCh <- id
	return nil
}

func (cs *State) getLightBlock(height int64) (types.LightBlock, error) {
	signedHeader, err := getSignedHeader(cs.blockStore, height)

	if err != nil {
		return types.LightBlock{}, err
	}

	validators, err := cs.stateStore.LoadValidators(height)
	if err != nil {
		return types.LightBlock{}, err
	}

	return types.LightBlock{SignedHeader: signedHeader, ValidatorSet: validators}, nil
}

func getSignedHeader(blockStore evidence.BlockStore, height int64) (*types.SignedHeader, error) {
	blockMeta := blockStore.LoadBlockMeta(height)
	if blockMeta == nil {
		return nil, fmt.Errorf("don't have header at height #%d", height)
	}
	commit := blockStore.LoadBlockCommit(height)
	if commit == nil {
		return nil, fmt.Errorf("don't have commit at height #%d", height)
	}
	return &types.SignedHeader{
		Header: &blockMeta.Header,
		Commit: commit,
	}, nil
}
