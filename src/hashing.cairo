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


func hashHeader{range_check_ptr}(untrustedHeader: SignedHeaderData)->(res_hash:felt):
    alloc_locals
    # create array

    let h0 = split_hash4(untrustedHeader.header.version)
    let h1 = split_hash4(untrustedHeader.header.chain_id)
    let h2 = split_hash4(untrustedHeader.header.height)
    let h3 = split_hash4(untrustedHeader.header.time)
    let h4 = split_hash4(untrustedHeader.header.last_block_id)
    let h5 = untrustedHeader.header.last_commit_hash
    let h6 = untrustedHeader.header.data_hash
    let h7 = untrustedHeader.header.validators_hash
    let h8 = untrustedHeader.header.next_validators_hash
    let h9 = untrustedHeader.header.consensus_hash
    let h10 = untrustedHeader.header.app_hash
    let h11 = untrustedHeader.header.last_results_hash
    let h12 = untrustedHeader.header.evidence_hash
    let h13 = split_hash4(untrustedHeader.header.proposer_address)
    # call merkleRootHash on the array 
    
    let (local all_array : felt*) = alloc()

    assert all_array[0] = h0
    assert all_array[1] = h1
    assert all_array[2] = h2
    assert all_array[3] = h3
    assert all_array[4] = h4
    assert all_array[5] = h5
    assert all_array[6] = h6
    assert all_array[7] = h7
    assert all_array[8] = h8
    assert all_array[9] = h9
    assert all_array[10] = h10
    assert all_array[11] = h11
    assert all_array[12] = h12
    assert all_array[13] = h13

    let (merkle_hash : felt) = merkleRootHash(all_array, 0, 14) 
    return(merkle_hash)
end

func canonicalPartSetHeaderHasher{
    pedersen_ptr : HashBuiltin*}(
    part_set_header: PartSetHeaderData)
    ->(res_hash:felt):

    alloc_locals
    local total: felt = part_set_header.total
    local hash: felt = part_set_header.hash
    let (res_hash) = hash2{hash_ptr=pedersen_ptr}(total, hash)

    return(res_hash)

end


func blockIDHasher{pedersen_ptr : HashBuiltin*}(block_id: BlockIDData)->(res_hash: felt):
    alloc_locals

    local bidd_hash: felt = block_id.hash
    local part_set_header: PartSetHeaderData = block_id.part_set_header

    let (psh_hash) = canonicalPartSetHeaderHasher(part_set_header)
    let (res_hash) = hash2{hash_ptr=pedersen_ptr}(bidd_hash, psh_hash)

    return(res_hash)
end

func hashCanonicalVoteNoTime{pedersen_ptr : HashBuiltin*}(
    CVData: CanonicalVoteData)->(res:felt):
    alloc_locals
    
    local type: felt = 1 # TODO stand in value for Type https://github.com/kelemeno/tendermint-stark/blob/main/types/canonical.go#L95
    local height: felt = CVData.height
    local round: felt = CVData.round
    local chain_id: ChainID= CVData.chain_id
    local block_id: BlockIDData= CVData.block_id

    let (res_bidd) = blockIDHasher(block_id = block_id) 
    
    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(type, height)
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, round)
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, res_bidd)

    local chain_id_array: felt* = chain_id.chain_id_array
    local chain_id_len: felt = chain_id.len

    let (res_4: felt) = recursive_hash(res_3, chain_id_array, chain_id_len )

    return(res_4)

end

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
