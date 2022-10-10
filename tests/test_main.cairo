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
    let public_key0: PublicKeyData  = PublicKeyData(ecdsa = 3)
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
    let public_key1: PublicKeyData  = PublicKeyData( ecdsa=3)
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
func test_real_data{range_check_ptr,
pedersen_ptr : HashBuiltin*,ecdsa_ptr: SignatureBuiltin* }()->():
    alloc_locals

    let (local chain_id_ptr: felt*) =alloc()
    assert chain_id_ptr[ 0 ]= 8387236823862306913
    assert chain_id_ptr[ 1 ]= 7597059414893672244
    assert chain_id_ptr[ 2 ]= 89
    let chain_id1= ChainID(chain_id_array =chain_id_ptr , len =  3 )

                # create the header
                let header1_trusted: LightHeaderData = LightHeaderData(
                version = ConsensusData(block = 11, app= 1),
                chain_id = chain_id1, #this is a placeholder value
                height = 2,
                time = TimestampData(nanos =1665151931427233364),  
                last_block_id = BlockIDData(hash = 1219492568353748522961385175398560022045211084077744157041414310328866365847, 
                part_set_header = PartSetHeaderData(total = 1,
                 hash = 299270193047064004969378663000590154483390054867708020979326236393115938810)),
                last_commit_hash = 1498271510730646755659970353717793250035207884109136878495495782083560767451,
                data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                validators_hash = 1351025416102681554064771619963301710049384731229741268662255212759968056239,
                next_validators_hash = 1351025416102681554064771619963301710049384731229741268662255212759968056239,
                consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                app_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                last_results_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
                proposer_address =  959049038717653807685574738020370930163330319766788613812220440751532913821
                )

                # create commit
                let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

                let signature_data_trusted: SignatureData = SignatureData(signature_r = 985398586621990122275983100321131939703422138503421411946288048708904351012 , signature_s = 281251156426036768541866356027292642704642634905777380095279248269447230577 )

                local commitsig_Absent_trusted : CommitSigData = CommitSigData(
                block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address =  959049038717653807685574738020370930163330319766788613812220440751532913821 ,
                timestamp = TimestampData(nanos=  1665151936898382403 ), signature= signature_data_trusted)

                let (local commitsig1_pointer_trusted: CommitSigData*) =alloc()   
                assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted
                let commitsig1_array_trusted = CommitSigDataArray(array = commitsig1_pointer_trusted, len = 1)

                let commit1_trusted: CommitData = CommitData(height =  2 , 
                round =  0 , 
                block_id= BlockIDData(
                                hash=  2284821295593198063123710006720712444148928407927158656805997299260106071789 ,
                                part_set_header = PartSetHeaderData(total =  1 , hash= 258477914966058813825669297963174491218502214597115966204771378567395552643 )),
                signatures = commitsig1_array_trusted
                )

                # create the header from these two
                let trusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)


                # create the header
                let header2_untrusted: LightHeaderData = LightHeaderData(
                version = ConsensusData(block = 11, app= 1),
                chain_id = chain_id1, #this is a placeholder value
                height = 3,
                time = TimestampData(nanos =1665151943800578978),  
                last_block_id = BlockIDData(hash = 2284821295593198063123710006720712444148928407927158656805997299260106071789, 
                part_set_header = PartSetHeaderData(total = 1,
                 hash = 258477914966058813825669297963174491218502214597115966204771378567395552643)),
                last_commit_hash = 2261574172014262501737200690624881752786588611242069053067938257225614294093,
                data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                validators_hash = 1351025416102681554064771619963301710049384731229741268662255212759968056239,
                next_validators_hash = 1351025416102681554064771619963301710049384731229741268662255212759968056239,
                consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                app_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                last_results_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
                proposer_address =  959049038717653807685574738020370930163330319766788613812220440751532913821
                )

                # create commit
                let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

                let signature_data_untrusted: SignatureData = SignatureData(signature_r = 1574721190176926169105209787622837978716177559848193672133231451039095203935 , signature_s = 862824085651123954590113231158027915942328566730529267229623323501715744334 )

                local commitsig_Absent_untrusted : CommitSigData = CommitSigData(
                block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address =  959049038717653807685574738020370930163330319766788613812220440751532913821 ,
                timestamp = TimestampData(nanos=  1665151948776730580 ), signature= signature_data_untrusted)

                let (local commitsig1_pointer_untrusted: CommitSigData*) =alloc()   
                assert commitsig1_pointer_untrusted[0] = commitsig_Absent_untrusted
                let commitsig1_array_untrusted = CommitSigDataArray(array = commitsig1_pointer_untrusted, len = 1)

                let commit2_untrusted: CommitData = CommitData(height =  3 , 
                round =  0 , 
                block_id= BlockIDData(
                                hash=  2305738582548230784621410770943766237088090405825828319143275642261022540889 ,
                                part_set_header = PartSetHeaderData(total =  1 , hash= 1398175902064534593451892233790074365091196483301868474567578764902236394164 )),
                signatures = commitsig1_array_untrusted
                )

                # create the header from these two
                let untrusted_header: SignedHeaderData = SignedHeaderData(header = header2_untrusted, commit = commit2_untrusted)


                # create validator array
                let (local ValidatorData_pointer0: ValidatorData*) =alloc()
                let public_key0: PublicKeyData  = PublicKeyData( ecdsa =  1589628517848176223185580531765365051928938383738138639102475288129137637464 )
                let validator_data0: ValidatorData =  ValidatorData(Address =  959049038717653807685574738020370930163330319766788613812220440751532913821 ,
                pub_key = public_key0, voting_power=  10 , proposer_priority =  0 )
                assert ValidatorData_pointer0[0] = validator_data0

                let validator_array0: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer0, len = 1)
                let validator_set0: ValidatorSetData = ValidatorSetData(validators = validator_array0, proposer = validator_data0, total_voting_power =10 )
                let currentTime2 = DurationData(nanos =  1665151943800579978 )
                let maxClockDrift= DurationData(nanos = 10)
                let trustingPeriod = DurationData(nanos = 99999999999999999999)

                verifyAdjacent(trustedHeader= trusted_header, untrustedHeader= untrusted_header, untrustedVals=validator_set0,
                        trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift) 

                return()
end
