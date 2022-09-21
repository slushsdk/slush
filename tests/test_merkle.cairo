%lang starknet
from src.main import (verifyNewHeaderAndVals, get_total_voting_power, voteSignBytes, verifySig, get_tallied_voting_power, verifyCommitLight, verifyAdjacent, verifyNonAdjacent)
from src.structs import (TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, BLOCK_ID_FLAG_UNKNOWN, BLOCK_ID_FLAG_ABSENT, BLOCK_ID_FLAG_COMMIT, BLOCK_ID_FLAG_NIL, MAX_TOTAL_VOTING_POWER, TimestampData, SignatureData, ChainID, CommitSigData, PartSetHeaderData, BlockIDData, DurationData, CommitSigDataArray, CommitData, CanonicalVoteData, ConsensusData, LightHeaderData, SignedHeaderData, ValidatorDataArray, PublicKeyData, ValidatorData, ValidatorSetData, FractionData )
from src.utils import (time_greater_than, isExpired, greater_than, recursive_comparison)
from src.hashing import ( hash_int64, hash_int64_array, hash_felt, hash_felt_array)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash)
from src.struct_hasher import ( hashHeader, canonicalPartSetHeaderHasher, hashBlockID, hashCanonicalVoteNoTime)

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem


@external
func test_get_split_point{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}() -> ():

    let res1: felt = get_split_point(5)
    assert res1 =4

    let res2: felt = get_split_point(2)
    assert res2 =2
    
    let res2: felt = get_split_point(25)
    assert res2 =16

    return()
end



func test_merkle_hash_complete_tree{range_check_ptr, pedersen_ptr : HashBuiltin*, hash_ptr : HashBuiltin*, bitwise_ptr: BitwiseBuiltin*}() -> ():
    alloc_locals
    let (node0 : felt) = hash_felt(6)
    let (node1 : felt) = hash_felt(11)
    let (node2 : felt) = hash_felt(40)
    let (node3 : felt) = hash_felt(69)

    let (local tree : felt*) = alloc()
    assert tree[0] = node0
    assert tree[1] = node1
    assert tree[2] = node2
    assert tree[3] = node3

    # with manual hashing
    let (node01 : felt) = hash2(node0, node1)
    let (node23 : felt) = hash2(node2, node3)
    let (node0123 : felt) = hash2(node01, node23)

    # with merkle function call
    let (node0123_m : felt) = merkleRootHash(tree, 0, 4)
    assert node0123 = node0123_m

    return ()
end

 #func test_merkle_hash_incomplete_tree() -> ():
 #    alloc_locals
 #    let (node0 : felt) = split_hash4(6)
 #    let (node1 : felt) = split_hash4(11)
 #    let (node2 : felt) = split_hash4(40)
 #    let (node3 : felt) = split_hash4(69)
 #
 #    let (local tree : felt) = alloc()
 #    assert tree[0] = node0
 #    assert tree[1] = node1
 #    assert tree[2] = node2
 #    assert tree[3] = node3
 #
 #    # with manual hashing
 #    let (node01 : felt) = hash2(node0, node1)
 #    let (node23 : felt) = hash2(node2, node3)
 #    let (node0123 : felt) = hash2(node01, node23)
 #
 #    # with merkle function call
 #    let (node0123_m : felt) = merkleRootHash(tree, 0, 4)
 #    assert node0123 = node0123_m
 #
 #    return ()
 #end
