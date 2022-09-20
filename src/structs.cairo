%lang starknet

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
    member validators_address: felt 
    member timestamp: TimestampData
    member signature: SignatureData 

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
    member last_commit_hash: felt 
    member data_hash: felt
    member validators_hash: felt 
    member next_validators_hash: felt  
    member consensus_hash: felt  
    member app_hash: felt  
    member last_results_hash: felt  
    member evidence_hash: felt  
    member proposer_address: felt  
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
    member Address: felt  
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