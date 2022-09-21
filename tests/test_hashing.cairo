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


func hasher{pedersen_ptr : HashBuiltin*}(a:felt, b:felt)->(res:felt):

    let (hash) = hash2{hash_ptr=pedersen_ptr}(a,b)
    %{print('ids.hash')%}
    %{print(ids.hash)%}
    return(hash)

end

@external
func test_hash{pedersen_ptr : HashBuiltin*}() -> (res:felt):

    let (res1) = hasher(1,2)
    %{print(ids.res1)%}
    return(res1)

end


@external
func test_psh_hasher{pedersen_ptr:HashBuiltin*, range_check_ptr}()->(res:felt):
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)
    let (res_psh) = canonicalPartSetHeaderHasher(part_set_header1)

    %{print(ids.res_psh)%}
    return(res_psh)
end

@external
func test_blockIDHasher{pedersen_ptr:HashBuiltin*, range_check_ptr}()->(res:felt):
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)
    let (res_bidd) = hashBlockID(block_id = blockid1)

    %{print(ids.res_bidd)%}
    return(res_bidd)
end

@external
func test_hashCanonicalVoteNoTime{pedersen_ptr:HashBuiltin*, range_check_ptr}()->(res:felt):
    alloc_locals
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    let time0 = TimestampData(nanos = 0)

    # create the comit content
    let signature_data: SignatureData = SignatureData(signature_r = 0, signature_s =1)

    local commitsig_Absent : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Absent, validators_address = 1,
    timestamp = time0, signature= signature_data)

    local commitsig_Commit : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = 1,
    timestamp = time0, signature= signature_data)

    let (local commitsig1_pointer: CommitSigData*) =alloc()
    let(_,ap_commitsig) = get_fp_and_pc()
    let commitsig_fp= cast(ap_commitsig, CommitSigData*)
    assert commitsig1_pointer[0] = commitsig_Absent
    let(fp_commitsig1) = get_ap()
    assert commitsig1_pointer[1] = commitsig_Commit
    let(fp_commitsig2) = get_ap()
    assert commitsig1_pointer[2] = commitsig_Commit
    assert commitsig1_pointer[3] = commitsig_Commit

    let commitsig1_array = CommitSigDataArray(array = commitsig1_pointer, len = 4)


    # comit content created

    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)


    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let (local chain_id_ptr: felt*) =alloc()

    assert chain_id_ptr[0] = 1

    assert chain_id_ptr[1] = 2


    let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = 2)
    # let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
    #     signatures = commitsig1_array)
    let CVData= CanonicalVoteData(TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType=1,
    height = 11100111, round = 1, block_id = blockid1,
    timestamp= time0, chain_id=chain_id1)
    let (res_hashCVNT) = hashCanonicalVoteNoTime(CVData= CVData)

    %{print(ids.res_hashCVNT)%}
    return(res_hashCVNT)
end


@external
func test_recursive_hash{pedersen_ptr : HashBuiltin*, range_check_ptr}()->():
    alloc_locals
    let (local to_hash_array: felt*)= alloc()
    assert to_hash_array[0] = 101
    assert to_hash_array[1] = 102
    assert to_hash_array[2] = 103

    let res_hash:felt = hash_int64_array(to_hash_array, 3)
    
    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(0, 101)
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, 102)
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, 103)
    let (res_4: felt) = hash2{hash_ptr=pedersen_ptr}(res_3, 3)

    assert res_4 = res_hash

return()


end

@external
func test_hash64{pedersen_ptr: HashBuiltin*, range_check_ptr}()->():

 
    let num1: felt = 10
    let num2: felt = 10
    let num3: felt =18446744073709551616
    let num4: felt =18
    let num5: felt = 10
    let num6: felt = 18446744073709551617
    

    hash_int64(num1)
    hash_int64(num4)
    hash_int64(num2)
    return()
end


@external
func test_split_felt_128{range_check_ptr}()->():
    let pow2_251: felt = 2**250
    let pow2_192: felt = 2**192
    let pow2_128: felt = 2**128
    let pow2_64: felt = 2**64

    const input1 = 1 * pow2_128+ 1

    let (high_high1, low_low1) =split_felt(input1)
    
    %{print('ids.high split')%}    
    %{print(ids.high_high1)%}    
 
    %{print(ids.low_low1)%}    
    
    assert high_high1  =1

    assert low_low1= 1
    return()
end

@external
func test_split_felt_64{range_check_ptr}()->():
    let pow2_251: felt = 2**250
    let pow2_192: felt = 2**192
    let pow2_128: felt = 2**128
    let pow2_64: felt = 2**64

    const input1 = pow2_251 + pow2_192 + pow2_128 + pow2_64 +1

    let (high_high1:felt, high_low1:felt, low_high1:felt, low_low1:felt) = split_felt_to_64(input1)
    
    assert high_high1  =2**58+1
    assert high_low1 = 1
    assert low_high1 = 1
    assert low_low1= 1

    let reconstructed1 = (high_high1*pow2_64 + high_low1 )* pow2_128 + low_high1 * pow2_64 + low_low1
    assert input1 = reconstructed1
    
    const input3 =1 
    let (high_high3, high_low3, low_high3, low_low3) = split_felt_to_64(input3)
    assert high_high3  =0
    assert high_low3 = 0
    assert low_high3 = 0
    assert low_low3= 1

    return()
end

@external
func test_split_hash4{pedersen_ptr: HashBuiltin*, range_check_ptr}()->():
    let pow2_251: felt = 2**250
    let pow2_192: felt = 2**192
    let pow2_128: felt = 2**128
    let pow2_64: felt = 2**64
    const input1 = pow2_251 + pow2_192 + pow2_128 + pow2_64 +1
    
    let high_high1: felt  =2**58+1
    let high_low1:felt  = 1
    let low_high1: felt = 1
    let low_low1: felt= 1
    let (res_hash_all1) = hash_felt(input1)
     
    let (res_hash01) = hash2{hash_ptr=pedersen_ptr}(0,high_high1)
    let (res_hash02) = hash2{hash_ptr=pedersen_ptr}(res_hash01,high_low1)
    let (res_hash03) = hash2{hash_ptr=pedersen_ptr}(res_hash02,low_high1)
    let (res_hash04) = hash2{hash_ptr=pedersen_ptr}(res_hash03,low_low1)
    let (res_hash05) = hash2{hash_ptr=pedersen_ptr}(res_hash04,4)

    assert res_hash_all1 = res_hash05

    const input3 =1 
    let (res_hash_all3) = hash_felt(input3)
    let high_high3:felt  =0
    let high_low3:felt = 0
    let low_high3:felt = 0
    let low_low3:felt= 1

    let (res_hash1) = hash2{hash_ptr=pedersen_ptr}(0,high_high3)
    let (res_hash2) = hash2{hash_ptr=pedersen_ptr}(res_hash1,high_low3)
    let (res_hash3) = hash2{hash_ptr=pedersen_ptr}(res_hash2,low_high3)
    let (res_hash4) = hash2{hash_ptr=pedersen_ptr}(res_hash3,low_low3)
    let (res_hash5) = hash2{hash_ptr=pedersen_ptr}(res_hash4,4)

    assert res_hash_all3 = res_hash5
    return()

end

@external
func test_hash_array{pedersen_ptr: HashBuiltin*, range_check_ptr}()->():

    # create array of felts to be split and hashed
    alloc_locals
    let (local to_hash_array: felt*)= alloc()
    assert to_hash_array[0] = 1
    assert to_hash_array[1] = 2


    # call the hash_array fn on this array

    let res_hash_test: felt = hash_felt_array(array_pointer=to_hash_array , array_pointer_len=2)

    # check that this res_hash is the same as hashing the single felt by hand

    let high_high3:felt  =0
    let high_low3:felt = 0
    let low_high3:felt = 0
    let low_low3:felt= 1
    
    let high_high4:felt  =0
    let high_low4:felt = 0
    let low_high4:felt = 0
    let low_low4:felt= 2

    let (res_hash1) = hash2{hash_ptr=pedersen_ptr}(0,high_high3)
    let (res_hash2) = hash2{hash_ptr=pedersen_ptr}(res_hash1,high_low3)
    let (res_hash3) = hash2{hash_ptr=pedersen_ptr}(res_hash2,low_high3)
    let (res_hash4) = hash2{hash_ptr=pedersen_ptr}(res_hash3,low_low3)

    let (res_hash5) = hash2{hash_ptr=pedersen_ptr}(res_hash4,high_high4)
    let (res_hash6) = hash2{hash_ptr=pedersen_ptr}(res_hash5,high_low4)
    let (res_hash7) = hash2{hash_ptr=pedersen_ptr}(res_hash6,low_high4)
    let (res_hash8) = hash2{hash_ptr=pedersen_ptr}(res_hash7,low_low4)

    let (res_hash_manual) = hash2{hash_ptr=pedersen_ptr}(res_hash8,8)

    assert res_hash_manual = res_hash_test

    return()

end


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

 @external
func test_recursive_comparison{pedersen_ptr:HashBuiltin*}()->(res:felt):
    alloc_locals
    
       
    let (local chain_id_ptr_one: felt*) =alloc()   
    assert chain_id_ptr_one[0] = 1 
    assert chain_id_ptr_one[1] = 2
       
    let (local chain_id_ptr_two: felt*) =alloc()   
    assert chain_id_ptr_two[0] = 1 
    assert chain_id_ptr_two[1] = 2 

    recursive_comparison(chain_id_ptr_one, chain_id_ptr_two, 2)
    
    return(1)
end