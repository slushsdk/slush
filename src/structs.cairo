%lang starknet

struct TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType {
    // In the original Solidity code, an enum is used
    // to represent the different types of blocks.
    // However, in Cairo there are no enums, so we use
    // the following constants
    // will take values of 0,1,2,3 based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/proto/TendermintLight.sol#L8870
    SignedMsgType: felt,
}

const SIGNED_MSG_TYPE_UNKNOWN = 0;
const SIGNED_MSG_TYPE_PREVOTE = 1;
const SIGNED_MSG_TYPE_PRECOMMIT = 2;
const SIGNED_MSG_TYPE_PROPOSAL = 3;

struct TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag {
    BlockIDFlag: felt,
}

const BLOCK_ID_FLAG_UNKNOWN = 0;
const BLOCK_ID_FLAG_ABSENT = 1;
const BLOCK_ID_FLAG_COMMIT = 2;
const BLOCK_ID_FLAG_NIL = 3;

const MAX_TOTAL_VOTING_POWER = 2 ** 59;

// TimestampData is done
struct TimestampData {
    nanos: felt,
}

struct SignatureData {
    signature_r: felt,
    signature_s: felt,
}

struct ChainID {
    chain_id_array: felt*,
    len: felt,
}

// CommitSigData is done
struct CommitSigData {
    block_id_flag: TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag,
    validators_address: felt,
    timestamp: TimestampData,
    signature: SignatureData,
}

// PartSetHeader is done
struct PartSetHeaderData {
    total: felt,
    hash: felt,
}

// BlockIDData is done
struct BlockIDData {
    hash: felt,
    part_set_header: PartSetHeaderData,
}

// DurationData is done
struct DurationData {
    nanos: felt,
}

struct CommitSigDataArray {
    array: CommitSigData*,
    len: felt,
}

struct CommitData {
    height: felt,
    round: felt,
    block_id: BlockIDData,
    signatures: CommitSigDataArray,
}

struct CanonicalVoteData {
    TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType: felt,
    height: felt,
    round: felt,
    block_id: BlockIDData,
    timestamp: TimestampData,
    chain_id: ChainID,
}

// ConsensusData is done
struct ConsensusData {
    block: felt,
    app: felt,
}

struct LightHeaderData {
    version: ConsensusData,  // TODO maybe this needs to be a pointer
    chain_id: ChainID,
    height: felt,
    time: TimestampData,
    last_block_id: BlockIDData,
    last_commit_hash: felt,
    data_hash: felt,
    validators_hash: felt,
    next_validators_hash: felt,
    consensus_hash: felt,
    app_hash: felt,
    last_results_hash: felt,
    evidence_hash: felt,
    proposer_address: felt,
}

struct SignedHeaderData {
    header: LightHeaderData,
    commit: CommitData,
}

// Array types
struct ValidatorDataArray {
    array: ValidatorData*,
    len: felt,
}

struct PublicKeyData {
    // member ed25519: felt # replace w bytes
    // member secp256k1: felt # replace w bytes
    // member sr25519: felt # replace w bytes
    ecdsa: felt,
}

struct ValidatorData {
    Address: felt,
    pub_key: PublicKeyData,
    voting_power: felt,
    proposer_priority: felt,
}

struct ValidatorSetData {
    validators: ValidatorDataArray,
    proposer: ValidatorData,
    total_voting_power: felt,
}

struct FractionData {
    numerator: felt,
    denominator: felt,
}
