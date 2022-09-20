%lang starknet
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem, assert_lt
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.cairo.common.uint256 import Uint256, uint256_mul, uint256_unsigned_div_rem, uint256_lt
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.alloc import alloc

from src.structs import (TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, BLOCK_ID_FLAG_UNKNOWN, BLOCK_ID_FLAG_ABSENT, BLOCK_ID_FLAG_COMMIT, BLOCK_ID_FLAG_NIL, MAX_TOTAL_VOTING_POWER, TimestampData, SignatureData, ChainID, CommitSigData, PartSetHeaderData, BlockIDData, DurationData, CommitSigDataArray, CommitData, CanonicalVoteData, ConsensusData, LightHeaderData, SignedHeaderData, ValidatorDataArray, PublicKeyData, ValidatorData, ValidatorSetData, FractionData )


# function for checking whether which time stamp is larger
# returns 1 if first is larger, 0 in both other cases
func time_greater_than{range_check_ptr}(
    t1: TimestampData,
    t2: TimestampData 
    )->(res:felt):
    alloc_locals

    let (is_le_val: felt) = is_le(t2.nanos, t1.nanos)

    if is_le_val == 1:
        # check if t1 is equal to t2
        tempvar t1_nanos: felt = t1.nanos
        tempvar t2_nanos: felt = t2.nanos
        tempvar time_diff: felt = t1_nanos - t2_nanos
        let (not_equal: felt) = is_not_zero(time_diff) 
        
        if not_equal == 1:
            return(1)
        else:
            return(0)
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
        nanos= header.header.time.nanos + trustingPeriod.nanos
    )

    let currentTime_TimestampData = TimestampData(
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

func recursive_comparison(
    array_one_ptr: felt*, array_two_ptr: felt*, len:felt)->(res:felt):
    alloc_locals
    # takes pointer and length as input
    # hashes it all together, number of len times

    if len == 0:
        return(1)
    end

    local val_one: felt = [array_one_ptr]
    local val_two: felt = [array_two_ptr]

    assert val_one = val_two

    let (res_hash: felt) = recursive_comparison(array_one_ptr + 1, array_two_ptr+1, len-1)

    return(1)

end