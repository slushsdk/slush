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


func hash_int64{range_check_ptr, pedersen_ptr : HashBuiltin*}(input: felt)->(res_hash: felt):
    alloc_locals
    
    # Check that 0 <= x < 2**64.
    [range_check_ptr] = input
    assert [range_check_ptr + 1] = 2 ** 64 - 1 - input
    let range_check_ptr = range_check_ptr + 2 

    let (res_hash) = hash2{hash_ptr=pedersen_ptr}(input, 1)
    
    
    return(res_hash)

end



func hash_int64_array{range_check_ptr, pedersen_ptr : HashBuiltin*}(
    array_pointer: felt*,
    array_pointer_len : felt )->
    (res_hash: felt):
    alloc_locals

    let current_hash :felt = hash_int64_array_recursive(array_pointer, array_pointer_len, 0)
    let (last_hash: felt) = hash2{hash_ptr=pedersen_ptr}(current_hash, array_pointer_len)
    
    return (last_hash)
end

func hash_int64_array_recursive{pedersen_ptr : HashBuiltin*, range_check_ptr}(
    array_ptr: felt*, 
    array_ptr_len: felt,
    previous_hash: felt)->(res_hash:felt):
    alloc_locals
   
    if  array_ptr_len == 0:
        return (previous_hash)
    end

    local current_int: felt = [array_ptr]

    # Check that 0 <= x < 2**64.
    [range_check_ptr] = current_int
    assert [range_check_ptr + 1] = 2 ** 64 - 1 - current_int
    let range_check_ptr = range_check_ptr + 2 

    let (current_hash: felt) = hash2{hash_ptr=pedersen_ptr}(previous_hash, current_int)

    let (res_hash: felt) = hash_int64_array_recursive(array_ptr+1,  array_ptr_len-1, current_hash)

    return(res_hash)

end

func split_felt_to_64{range_check_ptr}(input1: felt)->(
    high_high:felt, 
    high_low:felt, 
    low_high:felt, 
    low_low:felt):
    alloc_locals

    # split the felt into two 128 bit parts
    

    let (high:felt, low: felt) = split_felt(input1)

    let pow2_64: felt = 2**64

    # split these into further two parts with division
    let (high_high:felt, high_low: felt) = unsigned_div_rem(high, pow2_64)
    let (low_high:felt, low_low: felt) = unsigned_div_rem(low, pow2_64)

    return (high_high, high_low, low_high, low_low)
end

func split_and_hash{range_check_ptr, pedersen_ptr : HashBuiltin*}(
    previous_hash: felt, input1: felt)->(res_hash: felt):
    alloc_locals

    let (high_high, high_low, low_high, low_low) =split_felt_to_64(input1)

    # now that splitting is done, hash these together

    let (res_hash1) = hash2{hash_ptr=pedersen_ptr}(previous_hash,high_high)
    let (res_hash2) = hash2{hash_ptr=pedersen_ptr}(res_hash1,high_low)
    let (res_hash3) = hash2{hash_ptr=pedersen_ptr}(res_hash2,low_high)
    let (res_hash4) = hash2{hash_ptr=pedersen_ptr}(res_hash3,low_low)

    return(res_hash4)
end

func hash_felt{range_check_ptr, pedersen_ptr : HashBuiltin*}(input1: felt)->(res_hash: felt):
    alloc_locals

    let (res_hash4) = split_and_hash(previous_hash = 0, input1 = input1)
    let (res_hash5) = hash2{hash_ptr=pedersen_ptr}(res_hash4,4)

    return(res_hash5)
end

func hash_felt_array{range_check_ptr, pedersen_ptr : HashBuiltin*}(
    array_pointer: felt*,
    array_pointer_len : felt)->
    (res_hash: felt):
    alloc_locals

    let previous_hash: felt = hash_felt_array_recursive(array_pointer, array_pointer_len, 0)

    let res_hash: felt = hash2{hash_ptr=pedersen_ptr}(previous_hash, 4 * array_pointer_len)
    
    return(res_hash)
end

func hash_felt_array_with_prefix{range_check_ptr, pedersen_ptr : HashBuiltin*}(
    array_pointer: felt*,
    array_pointer_len : felt, 
    prefix: felt)->
    (res_hash: felt):
    alloc_locals

    let prefix_hash : felt = split_and_hash(0, prefix)

    let previous_hash: felt = hash_felt_array_recursive(array_pointer, array_pointer_len, prefix_hash)

    let res_hash: felt = hash2{hash_ptr=pedersen_ptr}(previous_hash, 4 * array_pointer_len + 4)
    
    return(res_hash)
end

func hash_felt_array_recursive{range_check_ptr, pedersen_ptr : HashBuiltin*}(
    array_pointer: felt*,
    array_pointer_len : felt,
    previous_hash: felt)->
    (res_hash: felt):
    alloc_locals

    if array_pointer_len ==0 :
        return (previous_hash)
    end

    let current_felt : felt = [array_pointer]

    let res_split_felt :felt = split_and_hash(previous_hash = previous_hash, input1 = current_felt)

    let res_hash: felt = hash_felt_array_recursive(array_pointer+1, array_pointer_len -1 , res_split_felt)
    
    return (res_hash)
end
