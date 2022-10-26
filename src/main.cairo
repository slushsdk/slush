%lang starknet
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem, assert_lt
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_mul,
    uint256_unsigned_div_rem,
    uint256_lt,
)
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.alloc import alloc

from src.structs import (
    TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType,
    TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag,
    BLOCK_ID_FLAG_UNKNOWN,
    BLOCK_ID_FLAG_ABSENT,
    BLOCK_ID_FLAG_COMMIT,
    BLOCK_ID_FLAG_NIL,
    MAX_TOTAL_VOTING_POWER,
    TimestampData,
    SignatureData,
    ChainID,
    CommitSigData,
    PartSetHeaderData,
    BlockIDData,
    DurationData,
    CommitSigDataArray,
    CommitData,
    CanonicalVoteData,
    ConsensusData,
    LightHeaderData,
    SignedHeaderData,
    ValidatorDataArray,
    PublicKeyData,
    ValidatorData,
    ValidatorSetData,
    FractionData,
)
from src.utils import (
    time_greater_than,
    isExpired,
    greater_than,
    recursive_comparison,
    get_total_voting_power,
    verifySig,
    blockIDEqual,
)
from src.hashing import hash_int64, hash_int64_array, hash_felt, hash_felt_array
from src.merkle import get_split_point, leafHash, innerHash, merkleRootHash
from src.struct_hasher import (
    hashHeader,
    canonicalPartSetHeaderHasher,
    hashBlockID,
    hashCanonicalVoteNoTime,
    hashValidatorSet,
)

func voteSignBytes{pedersen_ptr: HashBuiltin*, range_check_ptr}(
    counter: felt, commit: CommitData, chain_id: ChainID
) -> (timestamp: TimestampData, res_hash: felt) {
    alloc_locals;

    // get parts of CommitData
    // build a new CVData from this

    local height: felt = commit.height;
    local round: felt = commit.round;
    local signatures_array: CommitSigData* = commit.signatures.array;
    local this_signature: CommitSigData = signatures_array[counter];
    local timestamp: TimestampData = this_signature.timestamp;
    local block_id: BlockIDData = commit.block_id;

    let CVData: CanonicalVoteData = CanonicalVoteData(
        TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType=1,
        height=height,
        round=round,
        block_id=block_id,
        timestamp=timestamp,
        chain_id=chain_id,
    );

    let res_hash: felt = hashCanonicalVoteNoTime(CVData=CVData);

    // need to prepend time to the hash

    return (timestamp, res_hash);
}

func get_tallied_voting_power{
    pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*, range_check_ptr
}(
    counter: felt,
    commit: CommitData,
    signatures_len: felt,
    signatures: CommitSigData*,
    validators_len: felt,
    validators: ValidatorData*,
    chain_id: ChainID,
) -> (res: felt) {
    alloc_locals;

    if (signatures_len == 0) {
        return (0,);
    }

    local signature: CommitSigData = signatures[0];
    local val: ValidatorData = validators[0];

    tempvar BlockIDFlag = signature.block_id_flag.BlockIDFlag;
    tempvar valsize = ValidatorData.SIZE;

    if (BlockIDFlag != BLOCK_ID_FLAG_COMMIT) {
        let (rest_of_voting_power: felt) = get_tallied_voting_power(
            counter + 1,
            commit,
            signatures_len - 1,
            signatures + 5,
            validators_len - 1,
            validators + 4,
            chain_id=chain_id,
        );
        return (rest_of_voting_power,);
    }

    // create a message with voteSignBytes, pass signature to this and signatures_len
    // verify this message with verifySig

    let (timestamp: TimestampData, res_hash: felt) = voteSignBytes(counter, commit, chain_id);

    local timestamp_nanos: felt = timestamp.nanos;

    let (local voteSB_array: felt*) = alloc();
    assert voteSB_array[0] = timestamp_nanos;
    assert voteSB_array[1] = res_hash;

    let message1: felt = hash_felt_array(voteSB_array, 2);

    local commit_sig_signature: SignatureData = signature.signature;
    verifySig(val, message1, commit_sig_signature);

    let (rest_of_voting_power: felt) = get_tallied_voting_power(
        counter + 1,
        commit,
        signatures_len - 1,
        signatures + 5,
        validators_len - 1,
        validators + 4,
        chain_id=chain_id,
    );
    return (val.voting_power + rest_of_voting_power,);
}

func verifyNewHeaderAndVals{
    range_check_ptr, pedersen_ptr: HashBuiltin*, bitwise_ptr: BitwiseBuiltin*
}(
    untrustedHeader: SignedHeaderData,
    trustedHeader: SignedHeaderData,
    untrustedVals: ValidatorSetData,
    currentTime: DurationData,
    maxClockDrift: DurationData,
) -> (res: felt) {
    alloc_locals;

    // set of simple checks to see if the header is valid

    // check if the chain id is the same

    tempvar untrusted_chain_id: ChainID = untrustedHeader.header.chain_id;
    tempvar trusted_chain_id: ChainID = trustedHeader.header.chain_id;

    // check if the lengths of the two chain_ids are the same
    assert untrusted_chain_id.len = trusted_chain_id.len;

    local chain_id_len = untrusted_chain_id.len;

    // check if the content of the two chain_ids is the same
    tempvar untrusted_chain_id_array_ptr: felt* = untrusted_chain_id.chain_id_array;
    tempvar trusted_chain_id_array_ptr: felt* = trusted_chain_id.chain_id_array;

    recursive_comparison(untrusted_chain_id_array_ptr, trusted_chain_id_array_ptr, chain_id_len);

    // check if commit hights are the same
    tempvar untrusted_commit_height: felt = untrustedHeader.commit.height;
    tempvar untrusted_header_height: felt = untrustedHeader.header.height;
    assert untrusted_commit_height = untrusted_header_height;

    // check if the header hash is the one we expect
    let (untrusted_header_block_hash: felt) = hashHeader(untrustedHeader);
    tempvar untrusted_header_commit_block_id_hash: felt = untrustedHeader.commit.block_id.hash;
    assert untrusted_header_block_hash = untrusted_header_commit_block_id_hash;

    // check if the untrusted header height to be greater
    // than the trusted header height
    tempvar untrusted_height: felt = untrustedHeader.header.height;
    tempvar trusted_height: felt = trustedHeader.header.height;

    let untrusted_greater: felt = is_le(trusted_height + 1, untrusted_height);
    assert untrusted_greater = 1;

    // check if the untrusted header time is greater than the trusted header time
    tempvar untrusted_time: TimestampData = untrustedHeader.header.time;
    tempvar trusted_time: TimestampData = trustedHeader.header.time;
    let (untrusted_time_greater: felt) = time_greater_than(untrusted_time, trusted_time);
    assert untrusted_time_greater = 1;

    // check if the untrusted header time is greater than the current time
    tempvar untrusted_time: TimestampData = untrustedHeader.header.time;

    let driftTime: TimestampData = TimestampData(nanos=currentTime.nanos + maxClockDrift.nanos);
    let (untrusted_time_greater_current: felt) = time_greater_than(driftTime, untrusted_time);
    assert untrusted_time_greater_current = 1;

    // check if the header validators hash is the one supplied

    tempvar untrusted_valhash: felt = untrustedHeader.header.validators_hash;
    let (trusted_valhash: felt) = hashValidatorSet(untrustedVals);
    assert untrusted_valhash = trusted_valhash;

    return (1,);
}

func verifyCommitLight{range_check_ptr, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*}(
    vals: ValidatorSetData,
    chain_id: ChainID,
    blockID: BlockIDData,
    height: felt,
    commit: CommitData,
) -> (res: felt) {
    alloc_locals;

    local vals_validators_length: felt = vals.validators.len;
    tempvar commit_signatures_length: felt = commit.signatures.len;
    assert vals_validators_length = commit_signatures_length;

    tempvar commit_height = commit.height;
    assert height = commit_height;

    // following check is equivalent to: require(commit.block_id.isEqual(blockID), "invalid commit -- wrong block ID");

    blockIDEqual(blockID, commit.block_id);

    // get the commit_signatures pointer
    // get the validatordata pointer

    tempvar vals_validators_array: ValidatorData* = vals.validators.array;
    tempvar commit_signatures_array: CommitSigData* = commit.signatures.array;

    // call get_tallied_voting_power to get the counts
    let (tallied_voting_power: felt) = get_tallied_voting_power{ecdsa_ptr=ecdsa_ptr}(
        counter=0,
        commit=commit,
        signatures_len=commit_signatures_length,
        signatures=commit_signatures_array,
        validators_len=vals_validators_length,
        validators=vals_validators_array,
        chain_id=chain_id,
    );

    let (total_voting_power: felt) = get_total_voting_power(
        validators_len=vals_validators_length, validators=vals_validators_array
    );

    // let tallied_voting_power_uint= Uint256(low= 1, high=0 )
    let tallied_voting_power_uint = Uint256(low=tallied_voting_power, high=0);
    let total_voting_power_uint = Uint256(low=total_voting_power, high=0);

    let numerator = Uint256(low=2, high=0);
    let denominator = Uint256(low=3, high=0);

    // find 2/3 of the total voting power with multiplying by uint256_mul and dividing uint256_unsigned_div_rem

    let (mul_low, mul_high) = uint256_mul(a=total_voting_power_uint, b=numerator);

    let (div_quotient, div_remainder) = uint256_unsigned_div_rem(a=mul_low, div=denominator);

    // compare the value resulting from the dvsion to the tallied_voting_power_uint

    let (more_tallied_votes: felt) = uint256_lt(div_quotient, tallied_voting_power_uint);

    assert more_tallied_votes = 1;

    return (0,);
}

func verifyAdjacent{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
}(
    trustedHeader: SignedHeaderData,
    untrustedHeader: SignedHeaderData,
    untrustedVals: ValidatorSetData,
    trustingPeriod: DurationData,
    currentTime: DurationData,
    maxClockDrift: DurationData,
) -> (res: felt) {
    alloc_locals;

    // check if the headers come from adjacent blocks
    assert untrustedHeader.header.height = trustedHeader.header.height + 1;

    // check that header is expired
    let (expired: felt) = isExpired(
        header=untrustedHeader, trustingPeriod=trustingPeriod, currentTime=currentTime
    );

    // make sure the header is not expired
    assert expired = 0;

    verifyNewHeaderAndVals(
        untrustedHeader, trustedHeader, untrustedVals, currentTime, maxClockDrift
    );

    verifyCommitLight(
        vals=untrustedVals,
        chain_id=trustedHeader.header.chain_id,
        blockID=untrustedHeader.commit.block_id,
        height=untrustedHeader.header.height,
        commit=untrustedHeader.commit,
    );

    // return value if all the above code ran, ow the above fails and nothing returned
    return (1,);
}

struct HeaderArgs {
    consensus_data: ConsensusData,
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

struct CommitArgs {
    height: felt,
    round: felt,
    block_id: BlockIDData,
}

struct SignedHeaderArgs {
    header: HeaderArgs,
    commit: CommitArgs,
}

func createSignedHeader(
    commit_sig_array_len: felt,
    commit_sig_array: CommitSigData*,
    chain_id: ChainID,
    args: SignedHeaderArgs,
) -> SignedHeaderData {
    let header: LightHeaderData = LightHeaderData(
        version=args.header.consensus_data,
        chain_id=chain_id,
        height=args.header.height,
        time=args.header.time,
        last_block_id=args.header.last_block_id,
        last_commit_hash=args.header.last_commit_hash,
        data_hash=args.header.data_hash,
        validators_hash=args.header.validators_hash,
        next_validators_hash=args.header.next_validators_hash,
        consensus_hash=args.header.consensus_hash,
        app_hash=args.header.app_hash,
        last_results_hash=args.header.last_results_hash,
        evidence_hash=args.header.evidence_hash,
        proposer_address=args.header.proposer_address,
    );

    let signatures = CommitSigDataArray(array=commit_sig_array, len=commit_sig_array_len);
    let commit = CommitData(
        height=args.commit.height,
        round=args.commit.round,
        block_id=args.commit.block_id,
        signatures=signatures,
    );

    let signed_header = SignedHeaderData(header=header, commit=commit);
    return signed_header;
}

struct ValidatorSetArgs {
    proposer: ValidatorData,
    total_voting_power: felt,
}

struct VerificationArgs {
    current_time: DurationData,
    max_clock_drift: DurationData,
    trusting_period: DurationData,
}

// @storage_var
// func save_block() -> (untrusted_signed_header: SignedHeaderData
// ){
// }

@storage_var
func save_block() -> (untrusted_signed_header_hash: felt
){
}

@external
func initBlockData{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    syscall_ptr: felt*,

}(
    chain_id_array_len: felt,
    chain_id_array: felt*,
    trusted_commit_sig_array_len: felt,
    trusted_commit_sig_array: CommitSigData*,
    validator_array_len: felt,
    validator_array: ValidatorData*,
    trusted: SignedHeaderArgs,
    validator_set_args: ValidatorSetArgs,
) -> (res: felt) {
    let chain_id = ChainID(chain_id_array=chain_id_array, len=chain_id_array_len);


    let trusted_signed_header: SignedHeaderData= createSignedHeader(
        commit_sig_array_len=trusted_commit_sig_array_len,
        commit_sig_array=trusted_commit_sig_array,
        chain_id=chain_id,
        args=trusted,
    );

    let validators: ValidatorDataArray = ValidatorDataArray(
        array=validator_array, len=validator_array_len
    );
    let untrusted_vals = ValidatorSetData(
        validators=validators,
        proposer=validator_set_args.proposer,
        total_voting_power=validator_set_args.total_voting_power,
    );

    // get the markle root of the header 

    let (header_hash:felt) = hashHeader(trusted_signed_header);

    save_block.write(header_hash);
    return(1,);
} 



@external
func savedVerifyAdjacent{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
    syscall_ptr: felt*,
}(
    chain_id_array_len: felt,
    chain_id_array: felt*,
    trusted_commit_sig_array_len: felt,
    trusted_commit_sig_array: CommitSigData*,
    untrusted_commit_sig_array_len: felt,
    untrusted_commit_sig_array: CommitSigData*,
    validator_array_len: felt,
    validator_array: ValidatorData*,
    trusted: SignedHeaderArgs,
    untrusted: SignedHeaderArgs,
    validator_set_args: ValidatorSetArgs,
    verification_args: VerificationArgs,
) -> (res: felt) {
    alloc_locals;


    let chain_id = ChainID(chain_id_array=chain_id_array, len=chain_id_array_len);

    let trusted_signed_header = createSignedHeader(
        commit_sig_array_len=trusted_commit_sig_array_len,
        commit_sig_array=trusted_commit_sig_array,
        chain_id=chain_id,
        args=trusted,
    );
      // load the previously saved and hence trusted signed header
    let (local trusted_signed_header_saved_hash: felt) = save_block.read();
    
    // verify that the current passed header hashes to the saved value
    let (trusted_signed_header_hash:felt) = hashHeader(trusted_signed_header); 

    // assert these two hashes match, this makes sure the new block is
    // the same as the previous block
    assert trusted_signed_header_hash = trusted_signed_header_saved_hash;

    let untrusted_signed_header = createSignedHeader(
        commit_sig_array_len=untrusted_commit_sig_array_len,
        commit_sig_array=untrusted_commit_sig_array,
        chain_id=chain_id,
        args=untrusted,
    );

    let validators: ValidatorDataArray = ValidatorDataArray(
        array=validator_array, len=validator_array_len
    );
    let untrusted_vals = ValidatorSetData(
        validators=validators,
        proposer=validator_set_args.proposer,
        total_voting_power=validator_set_args.total_voting_power,
    );

    let (res_verify: felt) =  verifyAdjacent(
        trustedHeader=trusted_signed_header,
        untrustedHeader=untrusted_signed_header,
        untrustedVals=untrusted_vals,
        trustingPeriod=verification_args.trusting_period,
        currentTime=verification_args.current_time,
        maxClockDrift=verification_args.max_clock_drift,
    );

    // check if the above code ran by checking if res_verify =1 
    // if it runs, save the new header info

    assert res_verify = 1;
    
    let (untrusted_signed_header_hash :felt) = hashHeader(untrusted_signed_header);

    save_block.write(untrusted_signed_header_hash);


    return(1,);
}


@external
func externalVerifyAdjacent{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
}(
    chain_id_array_len: felt,
    chain_id_array: felt*,
    trusted_commit_sig_array_len: felt,
    trusted_commit_sig_array: CommitSigData*,
    untrusted_commit_sig_array_len: felt,
    untrusted_commit_sig_array: CommitSigData*,
    validator_array_len: felt,
    validator_array: ValidatorData*,
    trusted: SignedHeaderArgs,
    untrusted: SignedHeaderArgs,
    validator_set_args: ValidatorSetArgs,
    verification_args: VerificationArgs,
) -> (res: felt) {
    let chain_id = ChainID(chain_id_array=chain_id_array, len=chain_id_array_len);

    let trusted_signed_header = createSignedHeader(
        commit_sig_array_len=trusted_commit_sig_array_len,
        commit_sig_array=trusted_commit_sig_array,
        chain_id=chain_id,
        args=trusted,
    );
    let untrusted_signed_header = createSignedHeader(
        commit_sig_array_len=untrusted_commit_sig_array_len,
        commit_sig_array=untrusted_commit_sig_array,
        chain_id=chain_id,
        args=untrusted,
    );

    let validators: ValidatorDataArray = ValidatorDataArray(
        array=validator_array, len=validator_array_len
    );
    let untrusted_vals = ValidatorSetData(
        validators=validators,
        proposer=validator_set_args.proposer,
        total_voting_power=validator_set_args.total_voting_power,
    );

    return verifyAdjacent(
        trustedHeader=trusted_signed_header,
        untrustedHeader=untrusted_signed_header,
        untrustedVals=untrusted_vals,
        trustingPeriod=verification_args.trusting_period,
        currentTime=verification_args.current_time,
        maxClockDrift=verification_args.max_clock_drift,
    );
}

func verifyNonAdjacent{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
}(
    trustedHeader: SignedHeaderData,
    trustedVals: ValidatorSetData,
    untrustedHeader: SignedHeaderData,
    untrustedVals: ValidatorSetData,
    trustingPeriod: DurationData,
    currentTime: DurationData,
    maxClockDrift: DurationData,
    trustLevel: FractionData,
) -> (res: felt) {
    alloc_locals;

    tempvar untrusted_header_height = untrustedHeader.header.height;
    tempvar trusted_header_height = trustedHeader.header.height;
    if (untrusted_header_height == trusted_header_height + 1) {
        assert 1 = 2;
    }

    //##############
    // TODO Hash check
    //    require(
    //        trustedVals.hash() == trustedHeader.header.next_validators_hash.toBytes32(),
    //        "LC: headers trusted validators does not hash to latest trusted validators"
    //    );
    //##############

    let (expired: felt) = isExpired(
        header=untrustedHeader, trustingPeriod=trustingPeriod, currentTime=currentTime
    );

    // make sure the header is not expired
    assert expired = 0;

    verifyNewHeaderAndVals(
        untrustedHeader, trustedHeader, untrustedVals, currentTime, maxClockDrift
    );

    verifyCommitLight{ecdsa_ptr=ecdsa_ptr}(
        vals=untrustedVals,
        chain_id=trustedHeader.header.chain_id,
        blockID=untrustedHeader.commit.block_id,
        height=untrustedHeader.header.height,
        commit=untrustedHeader.commit,
    );
    return (0,);
}
