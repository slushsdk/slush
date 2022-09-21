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
                time = TimestampData(nanos =1663769358946378446),  
                last_block_id = BlockIDData(hash = 2110599985734858295412863406490629377965336117934340562320021174965435898498, 
                part_set_header = PartSetHeaderData(total = 1,
                 hash = 274183666224902687105195258436859570474413582506721790135412155908192862668)),
                last_commit_hash = 3087612259957745442819872992476248881132717952534770507246464028227020013101,
                data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                validators_hash = 3477642834395576490588349693842740072960104400590180929396721897116064206596,
                next_validators_hash = 3477642834395576490588349693842740072960104400590180929396721897116064206596,
                consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                app_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                last_results_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
                proposer_address =  3021902612929258215355125670977965371075894765947221985579468460507503167350
                )

        # create commit
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

    let signature_data_trusted: SignatureData = SignatureData(signature_r = 2701582553640073722287479510572320765479135014632156452308783267890534836421 , signature_s = 744030903242230059270114227596345849109476197842572198017374830407599095395 )

    local commitsig_Absent_trusted : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address =  3021902612929258215355125670977965371075894765947221985579468460507503167350 ,
    timestamp = TimestampData(nanos=  1663769358946378446 ), signature= signature_data_trusted)

    let (local commitsig1_pointer_trusted: CommitSigData*) =alloc()   
    assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted
    let commitsig1_array_trusted = CommitSigDataArray(array = commitsig1_pointer_trusted, len = 1)

    let commit1_trusted: CommitData = CommitData(height =  2 , 
    round =  0 , 
    block_id= BlockIDData(
            hash=  2587414859112737857242498905805936477805272479267567800644582199090428730146 ,
            part_set_header = PartSetHeaderData(total =  1 , hash= 483337217071686124247211359286321187262744876919163915226459371830079188443 )),
    signatures = commitsig1_array_trusted
    )
    
    # create the header from these two
    let trusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)


                # create the header
                let header1_trusted: LightHeaderData = LightHeaderData(
                version = ConsensusData(block = 11, app= 1),
                chain_id = chain_id1, #this is a placeholder value
                height = 3,
                time = TimestampData(nanos =1663769368168134405),  
                last_block_id = BlockIDData(hash = 2587414859112737857242498905805936477805272479267567800644582199090428730146, 
                part_set_header = PartSetHeaderData(total = 1,
                 hash = 483337217071686124247211359286321187262744876919163915226459371830079188443)),
                last_commit_hash = 2710555977775143422122063820768287627870563185030394851407308389084360455847,
                data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                validators_hash = 3477642834395576490588349693842740072960104400590180929396721897116064206596,
                next_validators_hash = 3477642834395576490588349693842740072960104400590180929396721897116064206596,
                consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                app_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
                last_results_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
                evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
                proposer_address =  3021902612929258215355125670977965371075894765947221985579468460507503167350
                )

                # create commit
                let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

                let signature_data_trusted: SignatureData = SignatureData(signature_r = 2926184493796786795700519421321559283329151668826672540115160138593665913288 , signature_s = 1058102136767600787954386781913870113442835793839264290550721720752037160014 )

                local commitsig_Absent_trusted : CommitSigData = CommitSigData(
                block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address =  3021902612929258215355125670977965371075894765947221985579468460507503167350 ,
                timestamp = TimestampData(nanos=  1663769368168134405 ), signature= signature_data_trusted)

                let (local commitsig1_pointer_trusted: CommitSigData*) =alloc()   
                assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted
                let commitsig1_array_trusted = CommitSigDataArray(array = commitsig1_pointer_trusted, len = 1)

                let commit1_trusted: CommitData = CommitData(height =  3 , 
                round =  0 , 
                block_id= BlockIDData(
                                hash=  1091936886505770701056409474826068197015190797293123129644710538068575693029 ,
                                part_set_header = PartSetHeaderData(total =  1 , hash= 2779914650167735288037857740361050728982473670768951782468769603507651739692 )),
                signatures = commitsig1_array_trusted
                )

                # create the header from these two
                let untrusted_header: SignedHeaderData = SignedHeaderData(header = header1_trusted, commit = commit1_trusted)

    
    # create validator array
    let (local ValidatorData_pointer0: ValidatorData*) =alloc()
    let public_key0: PublicKeyData  = PublicKeyData(ed25519= 0, secp256k1 = 1, sr25519 = 2, ecdsa =  2025234578498408058890108666190145032783195536560943200602811548792083685806 )
    let validator_data0: ValidatorData =  ValidatorData(Address =  3021902612929258215355125670977965371075894765947221985579468460507503167350 ,
    pub_key = public_key0, voting_power=  10 , proposer_priority =  0 )
    assert ValidatorData_pointer0[0] = validator_data0
                                                        
    let validator_array0: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer0, len = 1)
    let validator_set0: ValidatorSetData = ValidatorSetData(validators = validator_array0, proposer = validator_data0, total_voting_power =10 )
    let currentTime2 = DurationData(nanos =  1663769368168135405 )
    let maxClockDrift= DurationData(nanos = 10)
    let trustingPeriod = DurationData(nanos = 99999999999999999999)

    verifyAdjacent(trustedHeader= trusted_header, untrustedHeader= untrusted_header, untrustedVals=validator_set0,
                trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift) 
    return()

end
