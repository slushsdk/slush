%lang starknet
from src.main import (verifyAdjacent, SignedHeaderData,
DurationData, LightHeaderData, ConsensusData, TimestampData, PartSetHeaderData, 
BlockIDData, CommitData, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, CommitSigData )
from starkware.cairo.common.cairo_builtins import HashBuiltin

# func test_verifyAdjacent{syscall_ptr : felt*, range_check_ptr, pedersen_ptr : HashBuiltin*}():
@external
func test_verifyAdjacent() -> () :


    # create instances of the headers

    # let (smallest_ptr : MyStruct*) = search_sorted_lower(
    #     array_ptr=array_ptr, elm_size=2, n_elms=3, key=2
    # )
    let time1 = TimestampData(Seconds = 12, nanos = 0)
    let Tendermint_BlockIDFLag = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    let commitsig1 = CommitSigData( block_id_flag = Tendermint_BlockIDFLag, validators_address = 1, timestamp = time1, signature = 1)
    let consensus1 = ConsensusData(block = 1, app =1 )
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 1)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let header1  = LightHeaderData(
        version  = consensus1, chain_id = 4, height = 11100111, time = time1,
        last_block_id = blockid1, last_commit_hash = 1, data_hash = 1,
        validators_hash= 1, next_validators_hash = 2, consensus_hash = 3, 
        app_hash = 4, last_results_hash = 5, proposer_address = 6   
    )
    
    let header2  = LightHeaderData(
        version  = consensus1, chain_id = 4, height = 11100112, time = time1,
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
   return ()
end