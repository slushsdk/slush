%lang starknet
from src.main import (verifyNewHeaderAndVals, get_total_voting_power, voteSignBytes, verifySig, get_tallied_voting_power, verifyCommitLight, verifyAdjacent, verifyNonAdjacent)
from src.structs import (TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, BLOCK_ID_FLAG_UNKNOWN, BLOCK_ID_FLAG_ABSENT, BLOCK_ID_FLAG_COMMIT, BLOCK_ID_FLAG_NIL, MAX_TOTAL_VOTING_POWER, TimestampData, SignatureData, ChainID, CommitSigData, PartSetHeaderData, BlockIDData, DurationData, CommitSigDataArray, CommitData, CanonicalVoteData, ConsensusData, LightHeaderData, SignedHeaderData, ValidatorDataArray, PublicKeyData, ValidatorData, ValidatorSetData, FractionData )
from src.utils import (time_greater_than, isExpired, greater_than, recursive_comparison)
from src.hashing import ( hash_int64, hash_int64_array, hash_felt, hash_felt_array, split_felt_to_64)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash)
from src.struct_hasher import ( hashHeader, canonicalPartSetHeaderHasher, hashBlockID, hashCanonicalVoteNoTime)


from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem


# func test_verifyAdjacent{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
@external
func test_verifyAdjacent{range_check_ptr,
pedersen_ptr : HashBuiltin*,ecdsa_ptr: SignatureBuiltin* }() -> () :


    # create instances of the headers

    # let (smallest_ptr : MyStruct*) = search_sorted_lower(
    #     array_ptr=array_ptr, elm_size=2, n_elms=3, key=2
    # )
    let time0 = TimestampData( nanos = 0)
    let time01 = TimestampData(nanos = 1)
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)
    alloc_locals 
    
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
    %{print(ids.commitsig1_pointer )%}
    # tempvar commitsig1_pointer[0] = CommitSigData( block_id_flag = Tendermint_BlockIDFLag, validators_address = 1, timestamp = time0, signature = 1)
    assert commitsig1_pointer[0] = commitsig_Absent
    let(fp_commitsig1) = get_ap()
    %{print("ids.fp_commitsig1")%}
    assert commitsig1_pointer[1] = commitsig_Commit
    let(fp_commitsig2) = get_ap()
    %{print(ids.fp_commitsig1)%}
    %{print(ids.fp_commitsig2)%}
    assert commitsig1_pointer[2] = commitsig_Commit 
    assert commitsig1_pointer[3] = commitsig_Commit 

    let (local chain_id_ptr: felt*) =alloc()   
   
    assert chain_id_ptr[0] = 1 

    assert chain_id_ptr[1] = 2
    let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = 2)

    let commitsig1_array = CommitSigDataArray(array = commitsig1_pointer, len = 4)
    let consensus1 = ConsensusData(block = 1, app =1 )
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 1)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let header1  = LightHeaderData(
        version  = consensus1, chain_id = chain_id1, height = 11100111, time = time0,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, evidence_hash =1,  proposer_address = 6   
    )
    
    let header2  = LightHeaderData(
        version  = consensus1, chain_id =chain_id1, height = 11100112, time = time01,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, evidence_hash = 1, proposer_address = 6   
    )

    let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
        signatures = commitsig1_array)
    
    let comit2 = CommitData(height = 11100112, round = 1, block_id = blockid1,
        signatures = commitsig1_array)

    let trustedHeader1 = SignedHeaderData(header= header1, commit = comit1)
    let untrustedHeader1 = SignedHeaderData(header= header2, commit = comit2)

    # test whether the time comparison works

    let time1 = TimestampData( nanos = 9)
    let time2 = TimestampData(nanos = 10)
    let time3 = TimestampData(nanos = 11)
    
    let time4 = TimestampData(nanos = 9)
    let time5 = TimestampData(nanos = 10)
    let time6 = TimestampData(nanos = 11)
    
    let time7 = TimestampData(nanos = 9)
    let time8 = TimestampData(nanos = 10)
    let time9 = TimestampData(nanos = 11)


    let (time55) = time_greater_than(time5, time5)
    assert time55 = 0

    let (time54) = time_greater_than(time5, time4)
    assert time54 = 1
    
    let (time56) = time_greater_than(time5, time6)
    assert time56 = 0

    let (time51) = time_greater_than(time5, time1)
    assert time51 = 1
    
    let (time52) = time_greater_than(time5, time2)
    assert time52 = 0
    
    let (time57) = time_greater_than(time5, time7)
    assert time57 = 1 
    
    let (time59) = time_greater_than(time5, time9)
    assert time59 = 0

    # test whether the time comparison works
    let trustingPeriod = DurationData(nanos = 9)
    let currentTime = DurationData(nanos = 10)
    let maxClockDrift= DurationData(nanos = 10)

    let (expired: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime)

    assert expired = 1
    
    let currentTime2 = DurationData(nanos = 5)

    let (expired2: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime2)

    assert expired2 = 0

    let (local ValidatorData_pointer0: ValidatorData*) =alloc()
    let(fp_validators0,_) = get_fp_and_pc()
    let public_key0: PublicKeyData  = PublicKeyData(ed25519= 0, secp256k1 = 1, sr25519 = 2, ecdsa = 3)
    let validator_data0: ValidatorData =  ValidatorData(Address = 1, pub_key = public_key0, voting_power= 2, proposer_priority = 3)
    let validator_fp0 = cast(fp_validators0, ValidatorData*)
    assert ValidatorData_pointer0[0] = validator_data0
    let(fp_commitsig13) = get_ap()
    assert ValidatorData_pointer0[1] = validator_data0
    let(fp_commitsig14) = get_ap()
    assert ValidatorData_pointer0[2] = validator_data0
    let(fp_commitsig15) = get_ap()
    assert ValidatorData_pointer0[3] = validator_data0
    let(fp_commitsig16) = get_ap()
    %{print(ids.fp_commitsig13)%}
    %{print(ids.fp_commitsig14)%}
    %{print(ids.fp_commitsig15)%}
    %{print(ids.fp_commitsig16)%}
                                                        
    let validator_array0: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer0, len = 4)
    let validator_set0: ValidatorSetData = ValidatorSetData(validators = validator_array0, proposer = validator_data0, total_voting_power =3 )
    # verifyAdjacent{ecdsa_ptr: ecdsa_ptr}(trustedHeader= trustedHeader1, untrustedHeader= untrustedHeader1, untrustedVals=validator_set0,
    verifyAdjacent(trustedHeader= trustedHeader1, untrustedHeader= untrustedHeader1, untrustedVals=validator_set0,
    trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift) 


    # TODO write test for verifyNewHeaderAndVals
    

    # test verifyCommitLight
    # create inputs for verifyCommitLight function
    # PrivateKeyData
    let public_key1: PublicKeyData  = PublicKeyData(ed25519= 0, secp256k1 = 1, sr25519 = 2, ecdsa=3)
    let validator_data1: ValidatorData =  ValidatorData(Address = 1, pub_key = public_key1, voting_power= 2, proposer_priority = 3)

    let (local ValidatorData_pointer: ValidatorData*) =alloc()
    let(fp_validators,_) = get_fp_and_pc()
    let validator_fp = cast(fp_validators, ValidatorData*)
    assert ValidatorData_pointer[0] = validator_data1
    let(fp_commitsig3) = get_ap()
    assert ValidatorData_pointer[1] = validator_data1
    let(fp_commitsig4) = get_ap()

    assert ValidatorData_pointer[2] = validator_data1
    let(fp_commitsig5) = get_ap()
    assert ValidatorData_pointer[3] = validator_data1
    let(fp_commitsig6) = get_ap()
    %{print(ids.fp_commitsig3)%}
    %{print(ids.fp_commitsig4)%}
    %{print(ids.fp_commitsig5)%}
    %{print(ids.fp_commitsig6)%}
    
    let validator_array: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer, len = 4)
    
    let validator_set: ValidatorSetData = ValidatorSetData(validators = validator_array, proposer = validator_data1, total_voting_power =3 )

    # verifyCommitLight(vals = validator_set, chainID= 1, blockID = blockid1, height= 11100111, commit = comit1)

    # test get_tallied_voting_power recurive function for adding up voting power

    # use
        # commit comit1
        # 
    let (all_votes:felt)= get_tallied_voting_power(counter =0, commit = comit1, signatures_len =4, signatures = commitsig1_pointer, validators_len = 4, validators = ValidatorData_pointer, chain_id=chain_id1)
    let (total_voting_power:felt)= get_total_voting_power( validators_len = 4, validators = ValidatorData_pointer)
    %{print("ids.all_votes")%}
    %{print(ids.commitsig1_pointer)%}
    %{print(ids.all_votes)%}
    assert all_votes = 6
    assert total_voting_power= 8

    # call verifyCommitLight
    let blockid2 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let valsInstance: ValidatorSetData = ValidatorSetData(validators = validator_array, proposer = validator_data1, total_voting_power = total_voting_power)
    verifyCommitLight(vals = valsInstance , chain_id= chain_id1, blockID = blockid2, height = 11100111, commit = comit1)


    return ()
end



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

@external
func test_voteSignBytes{pedersen_ptr : HashBuiltin*, range_check_ptr}()->(res:felt):

    alloc_locals
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    let time0 = TimestampData(nanos = 0)
    let time1 = TimestampData(nanos = 0)
    
    # create the comit content
    let signature_data: SignatureData = SignatureData(signature_r = 0, signature_s =1)

    local commitsig_Absent : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Absent, validators_address = 1,
    timestamp = time0, signature= signature_data)

    local commitsig_Commit : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = 1,
    timestamp = time1, signature= signature_data)

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
    let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
        signatures = commitsig1_array)
    
    let (local chain_id_ptr: felt*) =alloc()   
   
    assert chain_id_ptr[0] = 1 

    assert chain_id_ptr[1] = 2
    let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = 2)

    let (timestamp1, res_hash1) = voteSignBytes(counter=1, commit= comit1, chain_id=chain_id1) 

    %{print('ids.res_hash1')%}
    %{print(ids.res_hash1)%}
    let (timestamp2, res_hash2) = voteSignBytes(counter=0, commit= comit1, chain_id=chain_id1) 

    %{print(ids.res_hash2)%}
    return(res_hash1) 

end


@external
func test_recursive_hash{pedersen_ptr : HashBuiltin*, range_check_ptr}()->():
    alloc_locals
    let (local to_hash_array: felt*)= alloc()
    assert to_hash_array[0] = 1
    assert to_hash_array[1] = 2
    assert to_hash_array[2] = 3

    let res_hash:felt = hash_int64_array(to_hash_array, 3)
    
    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(0, 1)
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, 2)
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, 3)

    %{print(ids.res_hash)%}
    %{print(ids.res_1)%}
    %{print(ids.res_2)%}
    %{print(ids.res_3)%}
    assert res_3 = res_hash

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

    let res_hash_test: felt = hash_int64_array(array_pointer=to_hash_array , array_pointer_len=2)

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
func test_real_data{range_check_ptr,
pedersen_ptr : HashBuiltin*,ecdsa_ptr: SignatureBuiltin* }()->():
    alloc_locals

    let (local chain_id_ptr: felt*) =alloc()   
   
    assert chain_id_ptr[0] = 8387236823862306913 

    assert chain_id_ptr[1] = 7597059414893672244
    assert chain_id_ptr[2] =6413125869375586304 

    let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = 2)
    # create the header
    # let header1_trusted: LightHeaderData = LightHeaderData(
    # version = ConsensusData(block = 11, app= 1),
    # chain_id = chain_id1, # this is stand in value
    # height = 1,
    # time = TimestampData(nanos = 1661775573134 ), # these are in fact mili seconds
    # last_block_id = BlockIDData(hash = 0, part_set_header = PartSetHeaderData(total = 0, hash = 0)),
    # last_commit_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
    # data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
    # validators_hash = 1657485403597653774201701838487158114962187584356757705905323730218210757700,
    # next_validators_hash = 1657485403597653774201701838487158114962187584356757705905323730218210757700,
    # consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
    # app_hash = 0,
    # last_results_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284,
    # evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
    # proposer_address =  2106537075444065953880442667644615794908289081863782843215853903740729500594
    # )
let header1_trusted: LightHeaderData = LightHeaderData(
                version = ConsensusData(block = 11, app= 1),
                chain_id = chain_id1, #this is a placeholder value
                height = 3,
                time = TimestampData(nanos =1662043945911823338),  
                last_block_id = BlockIDData(hash = 1350581887305670976219093551514712393476890349005115090105451481932891709769, 
                    part_set_header = PartSetHeaderData(total = 1,
                    hash = 34351677666749332546175138575145207723100782902257477037128735467314946355968
                    )
                ),
                last_commit_hash = 2047209812686578342061870540649056015269274731338538727853891749634521176952,
                data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                validators_hash = 1444267967370953617069503466938625532441190924391147000892864135511216879794,
                next_validators_hash = 1444267967370953617069503466938625532441190924391147000892864135511216879794,
                consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                app_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                last_results_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
                proposer_address =  2707867986766388890175803523717950431936316144166963265239064944701646763119)

    # create commit
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

    let signature_data_trusted: SignatureData = SignatureData(signature_r = 2095801340941636419840360658023681398297727134762625155808558340930323500895, signature_s =2156904530046987521468289483198879799152272108249727390456251522170296440743)

    local commitsig_Absent_trusted : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = 2106537075444065953880442667644615794908289081863782843215853903740729500594,
    timestamp = TimestampData(nanos= 1661775578517), signature= signature_data_trusted)

    let (local commitsig1_pointer_trusted: CommitSigData*) =alloc()   
    assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted
    let commitsig1_array_trusted = CommitSigDataArray(array = commitsig1_pointer_trusted, len = 1)

    let commit1_trusted: CommitData = CommitData(height = 1, 
    round = 0, 
    block_id= BlockIDData(
            hash= 917023189488941218194787075389384798279597946141998621209104598914929927209,
            part_set_header = PartSetHeaderData(total = 1, hash=2049127694060112449178420607861863570400312281348272756673744827068373319666)),
    signatures = commitsig1_array_trusted
    )
    
    # create the header from these two
    let trusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)

    # create the header
    let header1_untrusted: LightHeaderData = LightHeaderData(
    version = ConsensusData(block = 11, app= 1),
    chain_id = chain_id1, # this is stand in value
    height = 2,
    time = TimestampData(nanos = 1661775582928 ), # these are in fact mili seconds
    last_block_id = BlockIDData(hash = 0, part_set_header = PartSetHeaderData(total = 1, hash = 2049127694060112449178420607861863570400312281348272756673744827068373319666)),
    last_commit_hash = 3206510756383374436900628853280269837377965041174915829009643860453850809276,
    data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
    validators_hash =1657485403597653774201701838487158114962187584356757705905323730218210757700 ,
    next_validators_hash = 1657485403597653774201701838487158114962187584356757705905323730218210757700,
    consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
    app_hash = 0,
    last_results_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284,
    evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
    proposer_address =  2106537075444065953880442667644615794908289081863782843215853903740729500594
    )

    # create commit

    let signature_data_untrusted: SignatureData = SignatureData(signature_r = 302570576979, signature_s =365276247188)

    local commitsig_Absent_untrusted : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = 2106537075444065953880442667644615794908289081863782843215853903740729500594,
    timestamp = TimestampData(nanos= 1661775586591), signature= signature_data_untrusted)

    let (local commitsig1_pointer_untrusted: CommitSigData*) =alloc()   
    assert commitsig1_pointer_untrusted[0] = commitsig_Absent_untrusted
    let commitsig1_array_untrusted = CommitSigDataArray(array = commitsig1_pointer_untrusted, len = 1)

    let commit1_untrusted: CommitData = CommitData(height = 2, 
    round = 0, 
    block_id= BlockIDData(
            hash= 65543580197910598078846360355791800832815991148552255474111224726005073269504,
            part_set_header = PartSetHeaderData(total = 1, hash=1375208434809757366091983320647191940997877109629879522000479096080610380267)),
    signatures = commitsig1_array_untrusted    
    )
    
    # create the header from these two
    let untrusted_header: SignedHeaderData = SignedHeaderData(header = header1_untrusted, commit = commit1_untrusted)

    # create validator array
    let (local ValidatorData_pointer0: ValidatorData*) =alloc()
    let public_key0: PublicKeyData  = PublicKeyData(ed25519= 0, secp256k1 = 1, sr25519 = 2, ecdsa = 186354605339507257990914121517420953533283196103464706074217121236949050624)
    let validator_data0: ValidatorData =  ValidatorData(Address = 2106537075444065953880442667644615794908289081863782843215853903740729500594,
    pub_key = public_key0, voting_power= 10, proposer_priority = 0)
    assert ValidatorData_pointer0[0] = validator_data0
                                                        
    let validator_array0: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer0, len = 1)
    let validator_set0: ValidatorSetData = ValidatorSetData(validators = validator_array0, proposer = validator_data0, total_voting_power =1 )
    let currentTime2 = DurationData(nanos = 1661865949749)
    let maxClockDrift= DurationData(nanos = 10)
    let trustingPeriod = DurationData(nanos = 99999999999999999999)
 
    verifyAdjacent(trustedHeader= trusted_header, untrustedHeader= untrusted_header, untrustedVals=validator_set0,
    trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift) 

return()

end
