%lang starknet
from src.main import (verifyAdjacent, SignedHeaderData,
DurationData, LightHeaderData, ConsensusData, TimestampData,SignatureData, PartSetHeaderData, 
BlockIDData, CommitData, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, CommitSigData, 
CommitSigDataArray, time_greater_than, isExpired, PublicKeyData, ValidatorData,
ValidatorDataArray, ValidatorSetData, verifyCommitLight, get_tallied_voting_power,
get_total_voting_power, canonicalPartSetHeaderHasher, blockIDHasher, 
hashCanonicalVoteNoTime, voteSignBytes, CanonicalVoteData , )
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2


# func test_verifyAdjacent{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
@external
func test_verifyAdjacent{range_check_ptr,
pedersen_ptr : HashBuiltin*,ecdsa_ptr: SignatureBuiltin* }() -> () :


    # create instances of the headers

    # let (smallest_ptr : MyStruct*) = search_sorted_lower(
    #     array_ptr=array_ptr, elm_size=2, n_elms=3, key=2
    # )
    let time0 = TimestampData( nanos = 0)
    let time01 = TimestampData(nanos = 0)
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

    let commitsig1_array = CommitSigDataArray(array = commitsig1_pointer, len = 4)
    let consensus1 = ConsensusData(block = 1, app =1 )
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 1)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let header1  = LightHeaderData(
        version  = consensus1, chain_id = 4, height = 11100111, time = time0,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, evidence_hash =1,  proposer_address = 6   
    )
    
    let header2  = LightHeaderData(
        version  = consensus1, chain_id = 4, height = 11100112, time = time01,
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
    assert time52 = 1
    
    let (time57) = time_greater_than(time5, time7)
    assert time57 = 0
    
    let (time59) = time_greater_than(time5, time9)
    assert time59 = 0

    # test whether the time comparison works
    let trustingPeriod = DurationData(nanos = 9)
    let currentTime = DurationData(nanos = 10)
    let maxClockDrift= DurationData(nanos = 10)

    let (expired: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime)

    assert expired = 1
    
    let currentTime2 = DurationData(nanos = 10)

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
    let (all_votes:felt)= get_tallied_voting_power(counter =0, commit = comit1, signatures_len =4, signatures = commitsig1_pointer, validators_len = 4, validators = ValidatorData_pointer, chain_id=1)
    let (total_voting_power:felt)= get_total_voting_power( validators_len = 4, validators = ValidatorData_pointer)
    %{print("ids.all_votes")%}
    %{print(ids.commitsig1_pointer)%}
    %{print(ids.all_votes)%}
    assert all_votes = 6
    assert total_voting_power= 8

    # call verifyCommitLight
    let blockid2 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let valsInstance: ValidatorSetData = ValidatorSetData(validators = validator_array, proposer = validator_data1, total_voting_power = total_voting_power)
    verifyCommitLight(vals = valsInstance , chainID= 1, blockID = blockid2, height = 11100111, commit = comit1)


    return ()
end


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
func test_psh_hasher{pedersen_ptr:HashBuiltin*}()->(res:felt):
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)
    let (res_psh) = canonicalPartSetHeaderHasher(part_set_header1)

    %{print(ids.res_psh)%}
    return(res_psh)
end

@external
func test_blockIDHasher{pedersen_ptr:HashBuiltin*}()->(res:felt):
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)
    let (res_bidd) = blockIDHasher(block_id = blockid1) 

    %{print(ids.res_bidd)%}
    return(res_bidd)
end

@external
func test_hashCanonicalVoteNoTime{pedersen_ptr:HashBuiltin*}()->(res:felt):
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
    # let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
    #     signatures = commitsig1_array)
    let CVData= CanonicalVoteData(TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType=1,
    height = 11100111, round = 1, block_id = blockid1,
    timestamp= time0, chain_id=1)
    let (res_hashCVNT) = hashCanonicalVoteNoTime(CVData= CVData) 

    %{print(ids.res_hashCVNT)%}
    return(res_hashCVNT)
end

@external
func test_voteSignBytes{pedersen_ptr : HashBuiltin*}()->(res:felt):

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

    let (timestamp1, res_hash1) = voteSignBytes(counter=1, commit= comit1, chain_id=1) 

    %{print('ids.res_hash1')%}
    %{print(ids.res_hash1)%}
    let (timestamp2, res_hash2) = voteSignBytes(counter=0, commit= comit1, chain_id=1) 

    %{print(ids.res_hash2)%}
    return(res_hash1) 

end


@external
func test_sign_verify{}()->():

return()


end



@external
func test_real_data{range_check_ptr,
pedersen_ptr : HashBuiltin*,ecdsa_ptr: SignatureBuiltin* }()->():
    alloc_locals

    # create the header
    let header1_trusted: LightHeaderData = LightHeaderData(
    version = ConsensusData(block = 11, app= 1),
    chain_id = 1, # this is stand in value
    height = 1,
    time = TimestampData(nanos = 1661775573134 ), # these are in fact mili seconds
    last_block_id = BlockIDData(hash = 0, part_set_header = PartSetHeaderData(total = 0, hash = 0)),
    last_commit_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
    data_hash = 2089986280348253421170679821480865132823066470938446095505822317253594081284,
    validators_hash = 1657485403597653774201701838487158114962187584356757705905323730218210757700,
    next_validators_hash = 1657485403597653774201701838487158114962187584356757705905323730218210757700,
    consensus_hash = 2132461975834504200398180281070409533541683498016798668455504133351250391630,
    app_hash = 0,
    last_results_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284,
    evidence_hash =2089986280348253421170679821480865132823066470938446095505822317253594081284, 
    proposer_address =  2106537075444065953880442667644615794908289081863782843215853903740729500594
    )

    # create commit
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)

    let signature_data_trusted: SignatureData = SignatureData(signature_r = 302570576979, signature_s =365276247188)

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
    chain_id = 1, # this is stand in value
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