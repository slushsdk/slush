%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math_cmp import is_le, is_not_zero
from starkware.cairo.common.uint256 import Uint256, uint256_mul, uint256_unsigned_div_rem, uint256_lt
from starkware.cairo.common.signature import verify_ecdsa_signature
from starkware.cairo.common.hash import hash2


struct TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType:

    # In the original Solidity code, an enum is used
    # to represent the different types of blocks.
    # However, in Cairo there are no enums, so we use
    # the following constants
    # will take values of 0,1,2,3 based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/proto/TendermintLight.sol#L8870
    member SignedMsgType: felt 

end
    
const SIGNED_MSG_TYPE_UNKNOWN = 0
const SIGNED_MSG_TYPE_PREVOTE = 1
const SIGNED_MSG_TYPE_PRECOMMIT = 2
const SIGNED_MSG_TYPE_PROPOSAL = 3


struct TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag:

    member BlockIDFlag: felt 

end

const BLOCK_ID_FLAG_UNKNOWN = 0
const BLOCK_ID_FLAG_ABSENT = 1
const BLOCK_ID_FLAG_COMMIT = 2
const BLOCK_ID_FLAG_NIL = 3

const MAX_TOTAL_VOTING_POWER = 4611686018427387904 # == 1 << (63 - 1)

# TimestampData is done
struct TimestampData:
    member nanos: felt 
end

struct SignatureData:
    member signature_r: felt
    member signature_s: felt

end

struct ChainID:
    member chain_id_array: felt*
    member len: felt
end

# CommitSigData is done
struct CommitSigData:
    member block_id_flag: TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag
    member validators_address: felt # should be bytes
    member timestamp: TimestampData
    member signature: SignatureData # should be bytes

end

# PartSetHeader is done
struct PartSetHeaderData:
    member total: felt 
    member hash: felt

end

# BlockIDData is done
struct BlockIDData:
    member hash: felt 
    member part_set_header: PartSetHeaderData

end

# DurationData is done
struct DurationData:
    member nanos: felt 
end

struct CommitSigDataArray:
    member array: CommitSigData*
    member len: felt
end

# TODO: implement signatures as an array of unknown length
struct CommitData:
    member height: felt 
    member round: felt
    member block_id: BlockIDData 
    # the following line should be a list of CommitSigData
    member signatures: CommitSigDataArray 
    # the above line is invalid because is a pointer
end

# TODO: implement signatures as an array of unknown length
struct CanonicalVoteData:
    member TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType: felt 
    member height: felt 
    member round: felt 
    member block_id: BlockIDData 
    member timestamp: TimestampData
    member chain_id: ChainID 

    # the following line should be a list of CommitSigData
    # member signature: SignatureData 
    # the above line is invalid because is a pointer
end

# ConsensusData is done
struct ConsensusData:
    member block: felt 
    member app: felt 

end

struct LightHeaderData:
    member version: ConsensusData # TODO maybe this needs to be a pointer
    member chain_id: ChainID 
    member height: felt 
    member time: TimestampData
    member last_block_id: BlockIDData
    member last_commit_hash: felt # replace with bytes
    member data_hash: felt # replace with bytes
    member validators_hash: felt # replace with bytes
    member next_validators_hash: felt # replace with bytes
    member consensus_hash: felt # replace with bytes
    member app_hash: felt # replace with bytes
    member last_results_hash: felt # replace with bytes
    member evidence_hash: felt # replace with bytes
    member proposer_address: felt # replace with bytes
end

struct SignedHeaderData:
    member header: LightHeaderData
    member commit: CommitData
end

# Array types
struct ValidatorDataArray:
    member array: ValidatorData*
    member len: felt
end

struct PublicKeyData:
    member ed25519: felt # replace w bytes
    member secp256k1: felt # replace w bytes
    member sr25519: felt # replace w bytes
    member ecdsa: felt 
end

struct ValidatorData:
    member Address: felt # replace w bytes
    member pub_key: PublicKeyData
    member voting_power: felt 
    member proposer_priority: felt 
end

struct ValidatorSetData:
    member validators: ValidatorDataArray
    member proposer: ValidatorData
    member total_voting_power: felt 
end

struct FractionData:
    member numerator: felt
    member denominator: felt
end

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

# TODO change dummy hash function to a real one
func ourHashFunction{range_check_ptr}(untrustedHeader: SignedHeaderData)->(res:felt):
    return(11)
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


    return(1)
end

# the solidity code here is not very professional
# I remove the total_voting_power_parameter
# because we work with immutable variables
func get_total_voting_power(
    validators_len: felt,
    validators: ValidatorData*
) -> (res: felt):
    if validators_len == 0:
        return (0)
    end
    %{print(ids.validators_len)%}
    let (sum: felt) = get_total_voting_power(validators_len - 1, validators + 6)
    # TODO assert sum < MAX_TOTAL_VOTING_POWER
    let first_vals: ValidatorData = [validators]
    let voting_power: felt = first_vals.voting_power
    %{print('ids.voting_power')%}
    %{print(ids.voting_power)%}
    return (voting_power + sum)
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

func voteSignBytes{pedersen_ptr: HashBuiltin*}(
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


func verifySig{ecdsa_ptr: SignatureBuiltin*}(
    val: ValidatorData,
    message: felt, # bytes
    signature: SignatureData 
) -> (res: felt):
    alloc_locals

    # call verify_ecdsa_signature
    # here the two parts of the signature will be passed on from Tendermint
    local pub_key: felt = val.pub_key.ecdsa
    
    local sig_r = signature.signature_r
    local sig_s = signature.signature_s

    # behaves like an assert
    verify_ecdsa_signature{ecdsa_ptr=ecdsa_ptr}(message=message, public_key=pub_key,signature_r = sig_r , signature_s=sig_s )
    return(1)
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

func get_tallied_voting_power{pedersen_ptr : HashBuiltin*,
    ecdsa_ptr: SignatureBuiltin*}( 
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
            validators_len -1,
            validators +6, 
            chain_id=chain_id
        )
        return (rest_of_voting_power)
    end
    

    # create a message with voteSignBytes, pass signature to this and signatures_len
    # verify this message with verifySig

    let (timestamp: TimestampData,res_hash: felt) = voteSignBytes(counter, commit, chain_id)

    local timestamp_nanos: felt = timestamp.nanos
    let message1: felt = hash2{hash_ptr=pedersen_ptr}(timestamp_nanos, res_hash)
    let message: felt = hash2{hash_ptr=pedersen_ptr}(message1, message1)
    
    local commit_sig_signature: SignatureData = signature.signature
    verifySig(val, message, commit_sig_signature)
    
    
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
    i let (local vals_validators_length: felt) = vals_validators_length_temp
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
        chain_id=trustedHeader.header.chain_id, # please check this type guys
        blockID=untrustedHeader.commit.block_id,
        height=untrustedHeader.header.height, # TODO int64
        commit=untrustedHeader.commit
    )
    return (0)
end








