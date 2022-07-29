%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math_cmp import is_le, is_not_zero


struct TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag:

    # In the original Solidity code, an enum is used
    # to represent the different types of blocks.
    # However, in Cairo there are no enums, so we use
    # the following constants
    # will take values of 0,1,2,3 based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/proto/TendermintLight.sol#L8870
    member BlockIDFlag: felt 

end

# TimestampData is done
struct TimestampData:
    member Seconds: felt # TODO should be int64
    member nanos: felt # TODO should be int32
end


# CommitSigData is done
struct CommitSigData:

    member block_id_flag: TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag
    member validators_address: felt # TODO should be bytes
    member timestamp: TimestampData
    member signature: felt # TODO should be bytes

end

# PartSetHeader is done
struct PartSetHeaderData:
    member total: felt # TODO should be uint64
    member hash: felt # TODO should be bytes

end

# BlockIDData is done
struct BlockIDData:
    member hash: felt # TODO needs to be bytes
    member part_set_header: PartSetHeaderData

end

# DurationData is done
struct DurationData:
    member Seconds: felt # TODO should be int64
    member nanos: felt # TODO should be int32
end


# TODO: implement signatures as an array of unknown length
struct CommitData:
    member height: felt #TODO replace with int64
    member round: felt #TODO replace with int32
    member block_id: BlockIDData # TODO implement BlockIDData
    # the following line should be a list of CommitSigData
    member signatures: CommitSigData # TODO implement CommitSigData
end

# ConsensusData is done
struct ConsensusData:
    member block: felt # TODO replace with uint64
    member app: felt # TODO replace with uint64

end

struct LightHeaderData:
    member version: ConsensusData # TODO maybe this needs to be a pointer
    member chain_id: felt # TODO replace with hash of string
    member height: felt # TODO replace with int64
    member time: TimestampData
    member last_block_id: BlockIDData
    member last_commit_hash: felt # TODO replace with bytes
    member data_hash: felt # TODO replace with bytes
    member validators_hash: felt # TODO replace with bytes
    member next_validators_hash: felt # TODO replace with bytes
    member consensus_hash: felt # TODO replace with bytes
    member app_hash: felt # TODO replace with bytes
    member last_results_hash: felt # TODO replace with bytes
    member proposer_address: felt # TODO replace with bytes
    
end

# Done
struct SignedHeaderData:
    member header: LightHeaderData
    member commit: CommitData
end

# function for checking whether which time stamp is larger
# returns 1 if first is larger, 0 in both other cases
func time_greater_than{range_check_ptr}(
    t1: TimestampData,
    t2: TimestampData 
    )->(res:felt):
    alloc_locals

    let (is_le_val: felt) = is_le(t2.Seconds, t1.Seconds)

    if is_le_val == 1:
        # check if t1 is equal to t2
        # let (local t1S: felt) = t1.Seconds
        # let (local t2S: felt) = t2.Seconds
        tempvar t1S: felt = t1.Seconds
        tempvar t2S: felt = t2.Seconds 
        tempvar time_diff: felt = t1S - t2S
        let (not_equal: felt) = is_not_zero(time_diff) 
        
        if not_equal == 1:
            return(1)
        else:
        # they are equal, check nanos
            let (is_le_val_nanos: felt) = is_le(t2.nanos, t1.nanos)
            
            if is_le_val_nanos == 1:
                tempvar t1n: felt = t1.nanos
                tempvar t2n: felt = t2.nanos
                tempvar time_diff_nanos: felt = t1n - t2n
                let (not_equal_nanos: felt) = is_not_zero(time_diff_nanos)
            

                if not_equal_nanos == 1:
                    return(1)
                else:
                    return(0)
                end          

            else:
                return(0)
            end
        end 
    else:
        return(0)  
    end

end


# check if the header is valid
func isExpired{range_check_ptr}(
    header: SignedHeaderData,
    trustingPeriod: DurationData,
    currentTime: DurationData
    )->(res:felt):

    # add the trusting period to the current time
    # create new DurationData struct

    let expirationTime: TimestampData = TimestampData(
        Seconds= header.header.time.Seconds + trustingPeriod.Seconds,
        nanos= header.header.time.nanos + trustingPeriod.nanos
    )

    let currentTime_TimestampData = TimestampData(
        Seconds= currentTime.Seconds,
        nanos= currentTime.nanos
    )
    return time_greater_than(currentTime_TimestampData, expirationTime)

end

# returns 1 if a>b, else 0
func greater_than{range_check_ptr}(
    a: felt,
    b: felt
    )->(res:felt):
    let (is_le_val: felt) = is_le(b, a)
    if is_le_val == 1:
        # check if they are equal
        tempvar ab_diff: felt = a - b
        let (not_equal: felt) = is_not_zero(ab_diff) 
        if not_equal == 1:
            return(1)
        else:
            return(0)
        end 
    else:
        return(0)
    end

end

func verifyNewHeaderAndVals{range_check_ptr}(
    untrustedHeader: SignedHeaderData,
    # untrustedVals: ValidatorSetData, # TODO implement ValidatorSetData
    trustedHeader: SignedHeaderData,
    currentTime: DurationData,
    maxClockDrift: DurationData
    )->(res:felt):

    # set of simple checks to see if the header is valid

    # check if the chain id is the same

    tempvar untrusted_chain_id: felt = untrustedHeader.header.chain_id
    tempvar trusted_chain_id: felt = trustedHeader.header.chain_id
    assert untrusted_chain_id = trusted_chain_id

    # check if commit hights are the same
    tempvar untrusted_commit_height: felt = untrustedHeader.commit.height
    tempvar untrusted_header_height: felt = untrustedHeader.header.height
    assert untrusted_commit_height = untrusted_header_height

    # check if the header hash is the one we expect
    # TODO based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/utils/Tendermint.sol#L137

    # check if the untrusted header height to be greater
    # than the trusted header height
    tempvar untrusted_height: felt = untrustedHeader.header.height
    tempvar trusted_height: felt = trustedHeader.header.height

    let (untrusted_greater: felt) = greater_than(untrusted_height, trusted_height)
    assert untrusted_greater = 1

    # check if the untrusted header time is greater than the trusted header time
    tempvar untrusted_time: TimestampData = untrustedHeader.header.time
    tempvar trusted_time: TimestampData = trustedHeader.header.time
    let (untrusted_time_greater: felt) = time_greater_than(untrusted_time, trusted_time)
    assert untrusted_time_greater = 1

    # check if the untrusted header time is greater than the current time
    tempvar untrusted_time: TimestampData= untrustedHeader.header.time

    let driftTime: TimestampData = TimestampData(
        Seconds= currentTime.Seconds + maxClockDrift.Seconds,
        nanos= currentTime.nanos + maxClockDrift.nanos
    )
    let (untrusted_time_greater_current: felt) = time_greater_than(driftTime, untrusted_time )
    assert untrusted_time_greater_current = 1

    # check if the header validators hash is the onne supplied
    # TODO based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/utils/Tendermint.sol#L161


    return(1)
end



@external
func verifyAdjacent{range_check_ptr} (
    trustedHeader: SignedHeaderData,
    untrustedHeader: SignedHeaderData,
    # untrustedVals: ValidatorSetData,
    trustingPeriod: DurationData,
    currentTime: DurationData,
    maxClockDrift: DurationData

    # the following res returns a 0 or 1 boolean
) -> (res: felt) :
    
    # check if the headers come from adjacent blocks
    assert untrustedHeader.header.height = trustedHeader.header.height + 1

    # check that header is expired

    let (expired:felt) =  isExpired(
        header= untrustedHeader,
        trustingPeriod= trustingPeriod,
        currentTime= currentTime
    ) 

    # make sure the header is not expired
    assert expired = 0

    verifyNewHeaderAndVals(untrustedHeader, trustedHeader,
    currentTime, maxClockDrift)

    return (1)
end 


