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
from src.hashing import (
    // hash_int64,
    hash_int128_array,
    // split_felt_to_64,
    // hash_felt,
    hash_felt_array
)
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
func test_hash_int128_array{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    alloc_locals;
    let (local to_hash_array: felt*) = alloc();
    assert to_hash_array[0] = 101;
    assert to_hash_array[1] = 102;
    assert to_hash_array[2] = 103;

    let res_hash: felt = hash_int128_array(to_hash_array, 3);

    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(0, 101);
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, 102);
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, 103);
    let (res_4: felt) = hash2{hash_ptr=pedersen_ptr}(res_3, 3);

    // This output is fed into tendermint tests.
    %{ print(ids.res_hash) %}

    assert res_4 = res_hash;
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

    let low_low3: felt = 104;


    let low_low4: felt = 105;

    let (res_hash7) = hash2{hash_ptr=pedersen_ptr}(0, low_low3);
    let (res_hash8) = hash2{hash_ptr=pedersen_ptr}(res_hash7, low_low4);

    let (res_hash_manual) = hash2{hash_ptr=pedersen_ptr}(res_hash8, 2);
    assert res_hash_manual = res_hash_test;
    return ();
}
