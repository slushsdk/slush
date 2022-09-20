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


func recursive_hash{pedersen_ptr : HashBuiltin*}(
    prev_value: felt, commit_id_ptr: felt*, len: felt)->(res_hash:felt):
    alloc_locals
    # takes pointer and length as input
    # hashes it all together, number of len times

    if len == 0:
        return(prev_value)
    end

    local commit_id: felt = [commit_id_ptr]
    %{print(ids.commit_id)%}

    # hash the prev_value and commit_id together
    let (current_hash: felt) = hash2{hash_ptr=pedersen_ptr}(prev_value, commit_id)

    let (res_hash: felt) = recursive_hash(current_hash, commit_id_ptr+1, len-1)

    return(res_hash)

end

func hash_64{range_check_ptr, pedersen_ptr : HashBuiltin*}(input: felt)->(res_hash: felt):

    # Check that 0 <= x < 2**64.
    [range_check_ptr] = input
    assert [range_check_ptr + 1] = 2 ** 64 - 1 - input
    
    let (res_hash) = hash2{hash_ptr=pedersen_ptr}(input, 1)
    let range_check_ptr = range_check_ptr + 2 
    
    return(res_hash)

end

func split_felt_64{range_check_ptr}(input1: felt)->(high_high:felt, high_low:felt, low_high:felt, low_low:felt):

    # split the felt into two 128 bit parts
    # split these into further two parts with division

    let (high:felt, low: felt) = split_felt(input1)

    %{print('ids.high split')%}    
    %{print(ids.high)%}    
    %{print(ids.low)%}    


    let pow2_64: felt = 2**64

    let (high_high:felt, high_low: felt) = unsigned_div_rem(high, pow2_64)
    let (low_high:felt, low_low: felt) = unsigned_div_rem(low, pow2_64)

    return (high_high, high_low, low_high, low_low)
end

func split_hash{range_check_ptr, pedersen_ptr : HashBuiltin*}(
    previous_hash: felt, input1: felt)->(res_hash: felt):
    
    let (high_high, high_low, low_high, low_low) =split_felt_64(input1)

    # now that splitting is done, hash these together

    let (res_hash1) = hash2{hash_ptr=pedersen_ptr}(previous_hash,high_high)
    let (res_hash2) = hash2{hash_ptr=pedersen_ptr}(res_hash1,high_low)
    let (res_hash3) = hash2{hash_ptr=pedersen_ptr}(res_hash2,low_high)
    let (res_hash4) = hash2{hash_ptr=pedersen_ptr}(res_hash3,low_low)

    return(res_hash4)
end

func split_hash4{range_check_ptr, pedersen_ptr : HashBuiltin*}(input1: felt)->(res_hash: felt):
    

    let (res_hash4) = split_hash(previous_hash = 0, input1 = input1)
    let (res_hash5) = hash2{hash_ptr=pedersen_ptr}(res_hash4,4)

    return(res_hash5)
end

func hash_array{range_check_ptr, pedersen_ptr : HashBuiltin*}(
array_pointer: felt*, counter: felt, previous_hash:felt, total_len : felt )
->(res_hash: felt):

    if counter == total_len:

        let last_hash: felt = hash2{hash_ptr=pedersen_ptr}(previous_hash,4 * total_len)
        return(last_hash)

    end    

    let current_felt : felt = [array_pointer]

    %{print('ids.current_felt')%}
    %{print(ids.current_felt)%}
    %{print('ids.counter')%}
    %{print(ids.counter)%}

    let res_split_felt :felt = split_hash(previous_hash = previous_hash, input1 = current_felt)

    let res_hash: felt = hash_array(array_pointer+1, counter+1, res_split_felt, total_len =total_len )
    
    return(res_hash)

end
