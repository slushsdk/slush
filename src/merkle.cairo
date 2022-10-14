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
from src.utils import (time_greater_than, isExpired, greater_than, recursive_comparison)
from src.hashing import ( hash_int64, hash_int64_array, hash_felt, hash_felt_array, hash_felt_array_with_prefix)



# returns the largest power of two that is smaller than the input
func get_split_point{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(input: felt)->( res: felt):
    alloc_locals

    let (le: felt) =  is_le(1+1, input)
    #%{print(ids.input)%}
    #[range_check_ptr] = input
    #let range_check_ptr = range_check_ptr + 1

    if le ==1:

        let res : felt = get_split_point_rec(input, 1)
        return (res)
    else:
        assert 0=1
        return (0)
    end
end

func get_split_point_rec{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(input: felt, lower_bound: felt)->( res: felt):
    alloc_locals

    let le: felt =  is_le( 2 * lower_bound+1, input)

    if le == 1:
        let (res : felt) = get_split_point_rec(input, 2 * lower_bound)
        return (res)
    else:
        return(lower_bound)
    end
end

func leafHash{pedersen_ptr: HashBuiltin*, range_check_ptr}(leaf: felt)->(res_hash: felt):
    alloc_locals

    let leafPrefix: felt = 0 
    
    let (local leaf_array: felt*)= alloc()
    assert leaf_array[0] = leaf
     

    # call the hash_array fn on this array
    let res_hash: felt = hash_felt_array_with_prefix(array_pointer=leaf_array , array_pointer_len = 1, prefix = leafPrefix)

    return(res_hash)
end


func innerHash{range_check_ptr, pedersen_ptr : HashBuiltin*}(left: felt, right: felt)->(res_hash: felt):
    alloc_locals
    let innerPrefix: felt = 1 

    # create array with leafPrefix and leaf value

    let (local to_hash_array: felt*)= alloc()
    assert to_hash_array[0] = left
    assert to_hash_array[1] = right 

    # call the hash_array fn on this array
    let res_hash: felt = hash_felt_array_with_prefix(array_pointer=to_hash_array , array_pointer_len = 2, prefix = innerPrefix)

    return(res_hash)


end

func merkleRootHash{pedersen_ptr : HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(validator_array: felt*, start: felt, total: felt)->(res_hash: felt):
    alloc_locals
    let empty_hash = 0

    if total ==0:
       return(empty_hash)

    else:
        if total ==1:

            local current_validator: felt = validator_array[start]
            
            let res_hash: felt  = leafHash(current_validator)

            return(res_hash)

        else:

            let split_point:felt = get_split_point(total)

            let left: felt = merkleRootHash(validator_array, start, split_point)

            let new_start: felt = start + split_point
            let new_total: felt = total - split_point
            let right: felt = merkleRootHash(validator_array, new_start, new_total)

            let inner_hash: felt = innerHash(left, right)

            return(inner_hash)

        end
    end
end

