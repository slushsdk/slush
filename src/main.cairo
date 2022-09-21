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
from src.utils import (time_greater_than, isExpired, greater_than, recursive_comparison, get_total_voting_power,  verifySig)
from src.hashing import (hash_int64, hash_int64_array, hash_felt, hash_felt_array)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash)
from src.struct_hasher import ( hashHeader, canonicalPartSetHeaderHasher, hashBlockID, hashCanonicalVoteNoTime)

func voteSignBytes{pedersen_ptr: HashBuiltin*, range_check_ptr}(
    counter: felt,
    commit: CommitData,
    chain_id: ChainID,
    )->(timestamp: TimestampData ,res_hash :felt):
    alloc_locals

    # get parts of CommitData
    # build a new CVData from this
    
    local height: felt = commit.height
    local round: felt = commit.round
    local signatures_array: CommitSigData* = commit.signatures.array
    local this_signature: CommitSigData = signatures_array[counter]
    local timestamp: TimestampData = this_signature.timestamp
    local block_id: BlockIDData= commit.block_id

    let CVData: CanonicalVoteData = CanonicalVoteData(
    TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType= 1,
    height = height, round = round, block_id = block_id,
    timestamp= timestamp, chain_id= chain_id)

    let res_hash: felt = hashCanonicalVoteNoTime(CVData = CVData )

    # need to prepend time to the hash

    return(timestamp, res_hash)

end

func verifyNewHeaderAndVals{range_check_ptr}(
    untrustedHeader: SignedHeaderData,
    # TODO below line
    # untrustedVals: ValidatorSetData, 
    trustedHeader: SignedHeaderData,
    currentTime: DurationData,
    maxClockDrift: DurationData
    )->(res:felt):
    alloc_locals
    # set of simple checks to see if the header is valid

    # check if the chain id is the same

    tempvar untrusted_chain_id: ChainID= untrustedHeader.header.chain_id
    tempvar trusted_chain_id: ChainID= trustedHeader.header.chain_id

    # check if the lengths of the two chain_ids are the same
    assert untrusted_chain_id.len = trusted_chain_id.len

    local chain_id_len = untrusted_chain_id.len

    #check if the content of the two chain_ids is the same
    tempvar untrusted_chain_id_array_ptr: felt* = untrusted_chain_id.chain_id_array
    tempvar trusted_chain_id_array_ptr: felt* = untrusted_chain_id.chain_id_array

    recursive_comparison(untrusted_chain_id_array_ptr, trusted_chain_id_array_ptr, chain_id_len)

    # check if commit hights are the same
    tempvar untrusted_commit_height: felt = untrustedHeader.commit.height
    tempvar untrusted_header_height: felt = untrustedHeader.header.height
    assert untrusted_commit_height = untrusted_header_height

    # check if the header hash is the one we expect
    # TODO based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/utils/Tendermint.sol#L137
    # let (untrusted_header_block_hash: felt) = ourHashFunction(untrustedHeader)
    # tempvar untrusted_header_commit_block_id_hash: felt = untrustedHeader.commit.block_id.hash
    # assert untrusted_header_block_hash = untrusted_header_commit_block_id_hash 

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
        nanos= currentTime.nanos + maxClockDrift.nanos
    )
    let (untrusted_time_greater_current: felt) = time_greater_than(driftTime, untrusted_time )
    assert untrusted_time_greater_current = 1

    # check if the header validators hash is the onne supplied
    # TODO based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/utils/Tendermint.sol#L161
    # which is based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/proto/TendermintHelper.sol#L143


    return(1)
end





func get_tallied_voting_power{pedersen_ptr : HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*, range_check_ptr}( 
    counter: felt,
    commit: CommitData,
    signatures_len: felt,
    signatures: CommitSigData*,
    validators_len: felt,
    validators: ValidatorData*,
    chain_id : ChainID,

)->(res: felt):
    alloc_locals

    if signatures_len == 0:
        return (0)
    end

    local signature: CommitSigData = [signatures]
    local val: ValidatorData = [validators]

    tempvar BlockIDFlag = signature.block_id_flag.BlockIDFlag
    tempvar valsize = ValidatorData.SIZE

    if BlockIDFlag != BLOCK_ID_FLAG_COMMIT:
        let (rest_of_voting_power: felt) = get_tallied_voting_power(
            counter +1,
            commit,
            signatures_len - 1,
            signatures + 6,
            validators_len - 1,
            validators + 6, 
            chain_id=chain_id
        )
        return (rest_of_voting_power)
    end
    

    # create a message with voteSignBytes, pass signature to this and signatures_len
    # verify this message with verifySig

    let (timestamp: TimestampData,res_hash: felt) = voteSignBytes(counter, commit, chain_id)

    local timestamp_nanos: felt = timestamp.nanos
    let message1: felt = hash2{hash_ptr=pedersen_ptr}(timestamp_nanos, res_hash) # todo this is wrong. 
    
    local commit_sig_signature: SignatureData = signature.signature
    verifySig(val, message1, commit_sig_signature)
    
    
    let (rest_of_voting_power: felt) = get_tallied_voting_power(
        counter+1,
        commit, 
        signatures_len - 1,
        signatures + 6,
        validators_len -1 ,
        validators +6,
        chain_id=chain_id
    )
    return (val.voting_power + rest_of_voting_power)
end

# return 0 (false) or 1 (true)
func verifyCommitLight{range_check_ptr, pedersen_ptr: HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*}(
    vals: ValidatorSetData,
    chain_id: ChainID,
    blockID: BlockIDData,
    height: felt, 
    commit: CommitData,
)->(res: felt):
    alloc_locals
    local vals_validators_length: felt = vals.validators.len
    tempvar commit_signatures_length: felt = commit.signatures.len
    assert vals_validators_length = commit_signatures_length
    
    tempvar commit_height = commit.height
    assert height = commit_height

    # This is the only way to compare two structs (BlockID)
    # following checks are equivalent to: require(commit.block_id.isEqual(blockID), "invalid commit -- wrong block ID");
    # need to check all parts of the struct

    tempvar blockid_hash = blockID.hash
    tempvar blockid_part_set_header_total = blockID.part_set_header.total
    tempvar blockid_part_set_header_hash = blockID.part_set_header.hash

    tempvar commit_blockid_hash = commit.block_id.hash
    tempvar commit_blockid_part_set_header_total = commit.block_id.part_set_header.total
    tempvar commit_blockid_part_set_header_hash = commit.block_id.part_set_header.hash

    assert blockid_hash = commit_blockid_hash
    assert blockid_part_set_header_total = commit_blockid_part_set_header_total
    assert blockid_part_set_header_hash = commit_blockid_part_set_header_hash

    # get the commit_signatures pointer
    # get the validatordata pointer

    tempvar vals_validators_array: ValidatorData*= vals.validators.array
    tempvar commit_signatures_array: CommitSigData* = commit.signatures.array

    # call get_tallied_voting_power to get the counts
    let (tallied_voting_power: felt) = get_tallied_voting_power{ecdsa_ptr=ecdsa_ptr}(counter = 0,commit=commit,
     signatures_len=commit_signatures_length, signatures=commit_signatures_array,
      validators_len=vals_validators_length, validators=vals_validators_array, chain_id= chain_id)
    
    let (total_voting_power: felt) = get_total_voting_power(validators_len=vals_validators_length, validators=vals_validators_array)

    # let tallied_voting_power_uint= Uint256(low= 1, high=0 )
    let tallied_voting_power_uint = Uint256(low= tallied_voting_power, high=0 )
    let total_voting_power_uint= Uint256(low= total_voting_power, high=0 )

    let numerator  = Uint256(low= 2, high=0)
    let denominator  = Uint256(low= 3, high=0)

   # find 2/3 of the total voting power with multiplying by uint256_mul and dividing uint256_unsigned_div_rem

    let (mul_low , mul_high ) = uint256_mul(a= total_voting_power_uint,b= numerator)

    let (div_quotient , div_remainder ) =  uint256_unsigned_div_rem(a= mul_low, div= denominator )

    # compare the value resulting from the dvsion to the tallied_voting_power_uint

    let (more_tallied_votes:felt) = uint256_lt(div_quotient, tallied_voting_power_uint)

    assert more_tallied_votes=1


    return(0)
end

# @external
func verifyAdjacent{range_check_ptr, pedersen_ptr : HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*} (
    trustedHeader: SignedHeaderData,

    untrustedHeader: SignedHeaderData,
    untrustedVals: ValidatorSetData,
    trustingPeriod: DurationData,
    currentTime: DurationData,
    maxClockDrift: DurationData

    # the following res returns a 0 or 1 (boolean)
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

    verifyCommitLight(
        vals=untrustedVals,
        chain_id=trustedHeader.header.chain_id, 
        blockID=untrustedHeader.commit.block_id,
        height=untrustedHeader.header.height, 
        commit=untrustedHeader.commit
    )

    return (1)
end 

func verifyNonAdjacent{range_check_ptr, pedersen_ptr : HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*} (
    trustedHeader: SignedHeaderData,
    trustedVals: ValidatorSetData,
    untrustedHeader: SignedHeaderData,
    untrustedVals: ValidatorSetData,
    trustingPeriod: DurationData,
    currentTime: DurationData,
    maxClockDrift: DurationData,
    trustLevel: FractionData
) -> (res: felt):
    tempvar untrusted_header_height = untrustedHeader.header.height
    tempvar trusted_header_height = trustedHeader.header.height
    if untrusted_header_height == trusted_header_height + 1:
        assert 1 = 2
    end

    ###############
    # TODO Hash check
    #    require(
    #        trustedVals.hash() == trustedHeader.header.next_validators_hash.toBytes32(),
    #        "LC: headers trusted validators does not hash to latest trusted validators"
    #    );
    ###############


    let (expired:felt) =  isExpired(
        header= untrustedHeader,
        trustingPeriod= trustingPeriod,
        currentTime= currentTime
    ) 

    # make sure the header is not expired
    assert expired = 0

    verifyNewHeaderAndVals(untrustedHeader, trustedHeader,
    currentTime, maxClockDrift)

    verifyCommitLight{ecdsa_ptr=ecdsa_ptr}(
        vals=untrustedVals,
        chain_id=trustedHeader.header.chain_id, 
        blockID=untrustedHeader.commit.block_id,
        height=untrustedHeader.header.height, 
        commit=untrustedHeader.commit
    )
    return (0)
end


