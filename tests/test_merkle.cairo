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
    assert res2 =1
    
    let res3: felt = get_split_point(25)
    assert res3 =16

    let res5: felt = get_split_point(3)
    assert res5 = 2

    let res6: felt = get_split_point(4)
    assert res6 =2

    return()
end


@external
func test_merkle_hash_complete_tree{range_check_ptr, pedersen_ptr : HashBuiltin*,  bitwise_ptr: BitwiseBuiltin*}() -> ():
    alloc_locals
    
    let (local tree : felt*) = alloc()
    assert tree[0] = 5
    assert tree[1] = 10
    assert tree[2] = 15
    assert tree[3] = 20


    # with merkle function call
    let (node0123_m : felt) = merkleRootHash(tree, 0, 4)
    #Fed into TM
    %{print(ids.node0123_m)%}
    return ()
end

@external
func test_merkle_hash_noncomplete_tree{range_check_ptr, pedersen_ptr : HashBuiltin*,  bitwise_ptr: BitwiseBuiltin*}() -> ():
    alloc_locals
    
    let (local tree : felt*) = alloc()
    assert tree[0] = 3454952438923234006568527143781167235276775604066827568425481679972150643448
    assert tree[1] = 2494110571235400288533148571502202163537425285881062150149675116686078062864
    assert tree[2] = 2908682032041418908903105681227249033483541201006723240850136728317167492227
    assert tree[3] = 2599929233293119982501280579193581206158611315304505534385243879518502888628
    assert tree[4] =2206723481920075052107131543171542739217923834753038471674523378436884433248
    assert tree[5] =3196042820007611016667731428007167809703393661030333042255511753651389202253
    assert tree[6] =2089986280348253421170679821480865132823066470938446095505822317253594081284
    assert tree[7] =3081086906630340236863811480373298036427706612523827020334484978388108542248
    assert tree[8] =3081086906630340236863811480373298036427706612523827020334484978388108542248
    assert tree[9] =2132461975834504200398180281070409533541683498016798668455504133351250391630
    assert tree[10] =0
    assert tree[11] =2089986280348253421170679821480865132823066470938446095505822317253594081284
    assert tree[12] =2089986280348253421170679821480865132823066470938446095505822317253594081284
    assert tree[13] =2096651760584687198361717080648350102473644945561758734773364314748439283675

    # with merkle function call
    let (node0123_m : felt) = merkleRootHash(tree, 0, 14)
    #Fed into TM
    %{print(ids.node0123_m)%}
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
