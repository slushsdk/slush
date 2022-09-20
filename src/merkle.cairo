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

# TODO change dummy hash function to a real one
# hash together the contents of the block header and produce the state root
# as per https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/proto/TendermintHelper.sol#L116

# returns the largest power of two that is smaller than the input
func get_split_point{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}(input: felt)->( res: felt):

    let gt: felt =  greater_than(input, 1)

    if gt ==1:
        let and_input: felt = bitwise_and(input, input-1)
        if  and_input ==0:
            return(input)
        else:
            let res: felt = get_split_point(input-1)
            return(res)
        end
    else:
        return(1)
    end
end

func leafHash{pedersen_ptr: HashBuiltin*, range_check_ptr}(leaf_value: felt)->(res_hash: felt):
    alloc_locals

    let leafPrefix: felt = 0 # TODO, check if this is the correct type and value, maybe Uint?

    let hashedLeafPrefix: felt = hash_64(leafPrefix)
    # create array with leafPrefix and leaf value

    let (local to_hash_array: felt*) = alloc()
    assert to_hash_array[0] = hashedLeafPrefix 
    assert to_hash_array[1] = leaf_value

    # call the hash_array fn on this array

    let res_hash: felt = hash_array(array_pointer =to_hash_array , counter = 0, previous_hash = 0 , total_len = 2)

    return(res_hash)
end


func innerHash{range_check_ptr, pedersen_ptr : HashBuiltin*}(left: felt, right: felt)->(res_hash: felt):
    alloc_locals
    let innerPrefix: felt = 1 # TODO, check if this is the correct type and value, maybe Uint?

    let hashedLeafPrefix: felt = hash_64(innerPrefix)
    # create array with leafPrefix and leaf value

    let (local to_hash_array: felt*)= alloc()
    assert to_hash_array[0] = hashedLeafPrefix 
    assert to_hash_array[1] = left
    assert to_hash_array[2] = right 

    # call the hash_array fn on this array

    let res_hash: felt = hash_array(array_pointer =to_hash_array , counter = 0, previous_hash = 0 , total_len = 3)

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