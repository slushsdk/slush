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

// function for checking whether which time stamp is larger
// returns 1 if first is larger, 0 in both other cases
func time_greater_than{range_check_ptr}(t1: TimestampData, t2: TimestampData) -> (res: felt) {
    alloc_locals;

    let is_le_val: felt = is_le(t2.nanos + 1, t1.nanos);

    return (is_le_val,);
}

// check if the header is valid
func isExpired{range_check_ptr}(
    header: SignedHeaderData, trustingPeriod: DurationData, currentTime: DurationData
) -> (res: felt) {
    alloc_locals;

    // add the trusting period to the current time
    // create new DurationData struct

    let expirationTime: TimestampData = TimestampData(
        nanos=header.header.time.nanos + trustingPeriod.nanos
    );

    let currentTime_TimestampData = TimestampData(nanos=currentTime.nanos);
    return time_greater_than(currentTime_TimestampData, expirationTime);
}

// returns 1 if a>b, else 0
func greater_than{range_check_ptr}(a: felt, b: felt) -> (res: felt) {
    alloc_locals;

    let is_le_val: felt = is_le(b + 1, a);
    return (is_le_val,);
}

func recursive_comparison(array_one_ptr: felt*, array_two_ptr: felt*, len: felt) -> (res: felt) {
    alloc_locals;
    // takes pointer and length as input
    // hashes it all together, number of len times

    if (len == 0) {
        return (1,);
    }

    local val_one: felt = [array_one_ptr];
    local val_two: felt = [array_two_ptr];

    assert val_one = val_two;

    let (res_hash: felt) = recursive_comparison(array_one_ptr + 1, array_two_ptr + 1, len - 1);

    return (1,);
}

// removed the total_voting_power_parameter
// because we work with immutable variables
func get_total_voting_power{range_check_ptr}(validators_len: felt, validators: ValidatorData*) -> (
    res: felt
) {
    alloc_locals;

    if (validators_len == 0) {
        return (0,);
    }

    let (local sum: felt) = get_total_voting_power(validators_len - 1, validators + 4);

    let bool: felt = is_le(sum + 1, MAX_TOTAL_VOTING_POWER);
    assert bool = 1;

    let first_vals: ValidatorData = validators[0];
    let voting_power: felt = first_vals.voting_power;

    return (voting_power + sum,);
}

// message should be bytes
func verifySig{ecdsa_ptr: SignatureBuiltin*}(
    val: ValidatorData, message: felt, signature: SignatureData
) -> (res: felt) {
    alloc_locals;

    // call verify_ecdsa_signature
    // here the two parts of the signature will be passed on from Tendermint
    local pub_key: felt = val.pub_key.ecdsa;

    local sig_r = signature.signature_r;
    local sig_s = signature.signature_s;

    // behaves like an assert
    verify_ecdsa_signature{ecdsa_ptr=ecdsa_ptr}(
        message=message, public_key=pub_key, signature_r=sig_r, signature_s=sig_s
    );
    return (1,);
}

// This is the only way to compare two structs (BlockID)
// need to check all parts of the struct
func blockIDEqual{}(bID1: BlockIDData, bID2: BlockIDData) {
    alloc_locals;

    tempvar blockid_hash = bID1.hash;
    tempvar blockid_part_set_header_total = bID1.part_set_header.total;
    tempvar blockid_part_set_header_hash = bID1.part_set_header.hash;

    tempvar commit_blockid_hash = bID2.hash;
    tempvar commit_blockid_part_set_header_total = bID2.part_set_header.total;
    tempvar commit_blockid_part_set_header_hash = bID2.part_set_header.hash;

    assert blockid_hash = commit_blockid_hash;
    assert blockid_part_set_header_total = commit_blockid_part_set_header_total;
    assert blockid_part_set_header_hash = commit_blockid_part_set_header_hash;
    return ();
}
