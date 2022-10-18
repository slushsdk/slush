%lang starknet
from src.main import (
    verifyNewHeaderAndVals,
    get_total_voting_power,
    voteSignBytes,
    verifySig,
    get_tallied_voting_power,
    verifyCommitLight,
    verifyAdjacent,
    verifyNonAdjacent,
)
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
from src.utils import time_greater_than, isExpired, greater_than, recursive_comparison
from src.hashing import hash_int64, hash_int64_array, split_felt_to_64, hash_felt, hash_felt_array
from src.merkle import get_split_point, leafHash, innerHash, merkleRootHash
from src.struct_hasher import (
    hashHeader,
    canonicalPartSetHeaderHasher,
    hashBlockID,
    hashCanonicalVoteNoTime,
)

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem

@external
func test_hash_int64_array{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    alloc_locals;
    let (local to_hash_array: felt*) = alloc();
    assert to_hash_array[0] = 101;
    assert to_hash_array[1] = 102;
    assert to_hash_array[2] = 103;

    let res_hash: felt = hash_int64_array(to_hash_array, 3);

    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(0, 101);
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, 102);
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, 103);
    let (res_4: felt) = hash2{hash_ptr=pedersen_ptr}(res_3, 3);

    // This output is fed into tendermint tests.
    %{ print(ids.res_hash) %}

    assert res_4 = res_hash;
    return ();
}

// @external
// func test_hash_int64{pedersen_ptr: HashBuiltin*, range_check_ptr}()->():
//    let num: felt = 10
//    # let num_hash = -> kalman for the value
//    let res : felt = hash_int64(num)
//
//    assert res = num_hash
//
//    return()
// end

@external
func test_split_felt_to_64{range_check_ptr}() -> () {
    let pow2_251: felt = 2 ** 250;
    let pow2_192: felt = 2 ** 192;
    let pow2_128: felt = 2 ** 128;
    let pow2_64: felt = 2 ** 64;

    const input1 = pow2_251 + pow2_192 + pow2_128 + pow2_64 + 1;

    let (high_high1: felt, high_low1: felt, low_high1: felt, low_low1: felt) = split_felt_to_64(
        input1
    );

    assert high_high1 = 2 ** 58 + 1;
    assert high_low1 = 1;
    assert low_high1 = 1;
    assert low_low1 = 1;

    let reconstructed1 = (high_high1 * pow2_64 + high_low1) * pow2_128 + low_high1 * pow2_64 + low_low1;
    assert input1 = reconstructed1;

    const input3 = 1;
    let (high_high3, high_low3, low_high3, low_low3) = split_felt_to_64(input3);
    assert high_high3 = 0;
    assert high_low3 = 0;
    assert low_high3 = 0;
    assert low_low3 = 1;

    return ();
}

@external
func test_hash_felt{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    let pow2_251: felt = 2 ** 250;
    let pow2_192: felt = 2 ** 192;
    let pow2_128: felt = 2 ** 128;
    let pow2_64: felt = 2 ** 64;

    const input1 = pow2_251 + pow2_192 + pow2_128 + pow2_64 + 1;
    let (res_hash_all1) = hash_felt(input1);
    let high_high1: felt = 2 ** 58 + 1;
    let high_low1: felt = 1;
    let low_high1: felt = 1;
    let low_low1: felt = 1;
    let (res_hash01) = hash2{hash_ptr=pedersen_ptr}(0, high_high1);
    let (res_hash02) = hash2{hash_ptr=pedersen_ptr}(res_hash01, high_low1);
    let (res_hash03) = hash2{hash_ptr=pedersen_ptr}(res_hash02, low_high1);
    let (res_hash04) = hash2{hash_ptr=pedersen_ptr}(res_hash03, low_low1);
    let (res_hash05) = hash2{hash_ptr=pedersen_ptr}(res_hash04, 4);
    assert res_hash_all1 = res_hash05;

    const input3 = 1;
    let (res_hash_all3) = hash_felt(input3);
    let high_high3: felt = 0;
    let high_low3: felt = 0;
    let low_high3: felt = 0;
    let low_low3: felt = 1;
    let (res_hash1) = hash2{hash_ptr=pedersen_ptr}(0, high_high3);
    let (res_hash2) = hash2{hash_ptr=pedersen_ptr}(res_hash1, high_low3);
    let (res_hash3) = hash2{hash_ptr=pedersen_ptr}(res_hash2, low_high3);
    let (res_hash4) = hash2{hash_ptr=pedersen_ptr}(res_hash3, low_low3);
    let (res_hash5) = hash2{hash_ptr=pedersen_ptr}(res_hash4, 4);

    assert res_hash_all3 = res_hash5;
    return ();
}

@external
func test_hash_felt_array{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    // create array of felts to be split and hashed
    alloc_locals;
    let (local to_hash_array: felt*) = alloc();
    assert to_hash_array[0] = 104;
    assert to_hash_array[1] = 105;

    // call the hash_array fn on this array

    let res_hash_test: felt = hash_felt_array(array_pointer=to_hash_array, array_pointer_len=2);

    // To be fed into tendermint tests
    %{ print(ids.res_hash_test) %}

    // check that this res_hash is the same as hashing the single felt by hand

    let high_high3: felt = 0;
    let high_low3: felt = 0;
    let low_high3: felt = 0;
    let low_low3: felt = 104;

    let high_high4: felt = 0;
    let high_low4: felt = 0;
    let low_high4: felt = 0;
    let low_low4: felt = 105;

    let (res_hash1) = hash2{hash_ptr=pedersen_ptr}(0, high_high3);
    let (res_hash2) = hash2{hash_ptr=pedersen_ptr}(res_hash1, high_low3);
    let (res_hash3) = hash2{hash_ptr=pedersen_ptr}(res_hash2, low_high3);
    let (res_hash4) = hash2{hash_ptr=pedersen_ptr}(res_hash3, low_low3);

    let (res_hash5) = hash2{hash_ptr=pedersen_ptr}(res_hash4, high_high4);
    let (res_hash6) = hash2{hash_ptr=pedersen_ptr}(res_hash5, high_low4);
    let (res_hash7) = hash2{hash_ptr=pedersen_ptr}(res_hash6, low_high4);
    let (res_hash8) = hash2{hash_ptr=pedersen_ptr}(res_hash7, low_low4);

    let (res_hash_manual) = hash2{hash_ptr=pedersen_ptr}(res_hash8, 8);
    assert res_hash_manual = res_hash_test;
    return ();
}
