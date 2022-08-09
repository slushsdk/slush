%lang starknet
from src.main import (verifyAdjacent, SignedHeaderData,
DurationData, LightHeaderData, ConsensusData, TimestampData, PartSetHeaderData, 
BlockIDData, CommitData, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, CommitSigData, 
CommitSigDataArray, time_greater_than, isExpired, PrivateKeyData, ValidatorData,
ValidatorDataArray, ValidatorSetData, verifyCommitLight )
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc


# func test_verifyAdjacent{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
@external
func test_verifyAdjacent{range_check_ptr}() -> () :


    # create instances of the headers

    # let (smallest_ptr : MyStruct*) = search_sorted_lower(
    #     array_ptr=array_ptr, elm_size=2, n_elms=3, key=2
    # )
    let time0 = TimestampData(Seconds = 12, nanos = 0)
    let time01 = TimestampData(Seconds = 13, nanos = 0)
    let Tendermint_BlockIDFLag = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    alloc_locals 
    local commitsig1 : CommitSigData = CommitSigData( block_id_flag = Tendermint_BlockIDFLag, validators_address = 1, timestamp = time0, signature = 1)
     let (local commitsig1_pointer: CommitSigData*) =alloc()   
    # tempvar commitsig1_pointer[0] = CommitSigData( block_id_flag = Tendermint_BlockIDFLag, validators_address = 1, timestamp = time0, signature = 1)
    assert commitsig1_pointer[0] = commitsig1 

    let commitsig1_array = CommitSigDataArray(array = commitsig1_pointer, len = 1)
    let consensus1 = ConsensusData(block = 1, app =1 )
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 1)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let header1  = LightHeaderData(
        version  = consensus1, chain_id = 4, height = 11100111, time = time0,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, proposer_address = 6   
    )
    
    let header2  = LightHeaderData(
        version  = consensus1, chain_id = 4, height = 11100112, time = time01,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, proposer_address = 6   
    )

    let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
        signatures = commitsig1_array)
    
    let comit2 = CommitData(height = 11100112, round = 1, block_id = blockid1,
        signatures = commitsig1_array)

    let trustedHeader1 = SignedHeaderData(header= header1, commit = comit1)
    let untrustedHeader1 = SignedHeaderData(header= header2, commit = comit2)


   
    # test whether the time comparison works

    let time1 = TimestampData(Seconds = 12, nanos = 9)
    let time2 = TimestampData(Seconds = 12, nanos = 10)
    let time3 = TimestampData(Seconds = 12, nanos = 11)
    
    let time4 = TimestampData(Seconds = 13, nanos = 9)
    let time5 = TimestampData(Seconds = 13, nanos = 10)
    let time6 = TimestampData(Seconds = 13, nanos = 11)
    
    let time7 = TimestampData(Seconds = 14, nanos = 9)
    let time8 = TimestampData(Seconds = 14, nanos = 10)
    let time9 = TimestampData(Seconds = 14, nanos = 11)
    


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

    let trustingPeriod = DurationData(Seconds = 1, nanos = 9)
    let currentTime = DurationData(Seconds = 20, nanos = 10)
    let maxClockDrift= DurationData(Seconds = 20, nanos = 10)

    let (expired: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime)

    assert expired = 1
    
    let currentTime2 = DurationData(Seconds = 2, nanos = 10)

    let (expired2: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime2)

    assert expired2 = 0

    verifyAdjacent(trustedHeader= trustedHeader1, untrustedHeader= untrustedHeader1,
    trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift) 

    # TODO write test for verifyNewHeaderAndVals
    

    # test verifyCommitLight

    # create inputs for verifyCommitLight function

    # PrivateKeyData
    let private_key1: PrivateKeyData  = PrivateKeyData(ed25519= 0, secp256k1 = 1, sr25519 = 2)
    let validator_data1: ValidatorData =  ValidatorData(Address = 1, pub_key = private_key1, voting_power= 2, proposer_priority = 3)
    

    let (local ValidatorData_pointer: ValidatorData*) =alloc()
    assert ValidatorData_pointer[0] = validator_data1
    let validator_array: ValidatorDataArray = ValidatorDataArray(array = ValidatorData_pointer, len = 1)
    
    let validator_set: ValidatorSetData = ValidatorSetData(validators = validator_array, proposer = validator_data1, total_voting_power =3 )

    verifyCommitLight(vals = validator_set, chainID= 1, blockID = blockid1, height= 11100111, commit = comit1)

    return ()
end
