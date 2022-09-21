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
from src.hashing import ( hash_int64, hash_int64_array, hash_felt, hash_felt_array)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash)

func hashConsensus{range_check_ptr, pedersen_ptr : HashBuiltin*}(consensus : ConsensusData) -> (res_hash: felt):
    alloc_locals
    tempvar consensus_block = consensus.block
    tempvar consensus_app = consensus.app

    let (local consensus_array : felt*) = alloc()

    assert consensus_array[0] = consensus_block
    assert consensus_array[1] = consensus_app

    let (res: felt) = hash_int64_array(consensus_array, 2)
    return (res)
end





func hashHeader{range_check_ptr, pedersen_ptr : HashBuiltin*, bitwise_ptr: BitwiseBuiltin*}(untrustedHeader: SignedHeaderData)->(res_hash:felt):
    alloc_locals
    # create array

    
    let (h0 : felt)  = hashConsensus(untrustedHeader.header.version)
    let (h1 : felt)  = hash_int64_array(untrustedHeader.header.chain_id.chain_id_array, untrustedHeader.header.chain_id.len)
    let (h2 : felt)  = hash_int64(untrustedHeader.header.height)
    let (h3 : felt)  = hashTime(untrustedHeader.header.time)
    let (h4 : felt)  = hashBlockID(untrustedHeader.header.last_block_id)
    tempvar h5       = untrustedHeader.header.last_commit_hash
    tempvar h6       = untrustedHeader.header.data_hash
    tempvar h7       = untrustedHeader.header.validators_hash
    tempvar h8 = untrustedHeader.header.next_validators_hash
    tempvar h9 = untrustedHeader.header.consensus_hash
    tempvar h10 = untrustedHeader.header.app_hash
    tempvar h11 = untrustedHeader.header.last_results_hash
    tempvar h12 = untrustedHeader.header.evidence_hash
    tempvar h13 = untrustedHeader.header.proposer_address
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
    pedersen_ptr : HashBuiltin*, range_check_ptr}(
    part_set_header: PartSetHeaderData)
    ->(res_hash:felt):
    alloc_locals

    let total: felt = part_set_header.total
    let hash: felt = part_set_header.hash
    let total_hash : felt = hash_int64(total)

    let (local all_array : felt*) = alloc()

    assert all_array[0] = total_hash
    assert all_array[1] = hash

    let (res_hash) = hash_felt_array(all_array, 2)

    return(res_hash)
end

func hashTime{range_check_ptr, pedersen_ptr : HashBuiltin*}(time: TimestampData)-> (res_hash:felt):
    let res: felt = hash_int64(time.nanos)
    return (res)
end

func hashBlockID{pedersen_ptr : HashBuiltin*, range_check_ptr}(block_id: BlockIDData)->(res_hash: felt):
    alloc_locals

    local bid_hash: felt = block_id.hash
    local part_set_header: PartSetHeaderData = block_id.part_set_header

    let (psh_hash) = canonicalPartSetHeaderHasher(part_set_header)

    let (local all_array : felt*) = alloc()

    assert all_array[0] = bid_hash
    assert all_array[1] = psh_hash

    let (res_hash) = hash_felt_array(all_array, 2)

    return(res_hash)
end

func hashCanonicalVoteNoTime{pedersen_ptr : HashBuiltin*, range_check_ptr}(
    CVData: CanonicalVoteData)->(res:felt):
    alloc_locals
    
    local type: felt = 1 # TODO stand in value for Type https://github.com/kelemeno/tendermint-stark/blob/main/types/canonical.go#L95
    local height: felt = CVData.height
    local round: felt = CVData.round
    local chain_id: ChainID= CVData.chain_id
    local block_id: BlockIDData= CVData.block_id

    let (res_bidd) = hashBlockID(block_id = block_id) 
    
    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(type, height)
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, round)
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, res_bidd)

    local chain_id_array: felt* = chain_id.chain_id_array
    local chain_id_len: felt = chain_id.len

    let (hash_type : felt) = hash_int64(type)
    let (hash_height : felt) = hash_int64(height)
    let (hash_round : felt) = hash_int64(round)
    let (hash_block_id : felt) = hash_int64(block_id.hash)
    let (hash_chain_id : felt) = hash_int64_array(chain_id_array, chain_id_len)

    let (local all_array : felt*) = alloc()
    assert all_array[0] = hash_type
    assert all_array[1] = hash_height
    assert all_array[2] = hash_round
    assert all_array[3] = hash_block_id
    assert all_array[4] = hash_chain_id

    let (hash_res : felt) = hash_int64_array(all_array, 5)

    return(hash_res)

end
