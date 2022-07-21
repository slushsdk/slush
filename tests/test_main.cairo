%lang starknet
from src.main import (verifyAdjacent, SignedHeaderData,
DurationData, LightHeaderData, ConsensusData, TimestampData, PartSetHeaderData, 
BlockIDData, CommitData, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, CommitSigData, 
time_greater_than, isExpired )
from starkware.cairo.common.cairo_builtins import HashBuiltin

# func test_verifyAdjacent{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
@external
func test_verifyAdjacent{range_check_ptr}() -> () :


    # create instances of the headers

    # let (smallest_ptr : MyStruct*) = search_sorted_lower(
    #     array_ptr=array_ptr, elm_size=2, n_elms=3, key=2
    # )
    let time0 = TimestampData(Seconds = 12, nanos = 0)
    let Tendermint_BlockIDFLag = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    let commitsig1 = CommitSigData( block_id_flag = Tendermint_BlockIDFLag, validators_address = 1, timestamp = time0, signature = 1)
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
        version  = consensus1, chain_id = 4, height = 11100112, time = time0,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, proposer_address = 6   
    )

    let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
        signatures = commitsig1)
    
    let comit2 = CommitData(height = 11100112, round = 1, block_id = blockid1,
        signatures = commitsig1)

    let trustedHeader1 = SignedHeaderData(header= header1, commit = comit1)
    let unustedHeader1 = SignedHeaderData(header= header2, commit = comit2)


   verifyAdjacent(trustedHeader= trustedHeader1, untrustedHeader= unustedHeader1) 
   
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

    let (expired: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime)

    assert expired = 1

    return ()
end