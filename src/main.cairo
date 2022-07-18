%lang starknet
from starkware.cairo.common.math import assert_nn
from starkware.cairo.common.cairo_builtins import HashBuiltin

struct TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag:

    # In the original Solidity code, an enum is used
    # to represent the different types of blocks.
    # However, in Cairo there are no enums, so we use
    # the following constants
    # will take values of 0,1,2,3 based on https://github.com/ChorusOne/tendermint-sol/blob/main/contracts/proto/TendermintLight.sol#L8870
    member BlockIDFlag: felt 

end

# TimestampData is done
struct TimestampData:
    member Seconds: felt # TODO should be int64
    member nanos: felt # TODO should be int32
end


# CommitSigData is done
struct CommitSigData:

    member block_id_flag: TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag
    member validators_address: felt # TODO should be bytes
    member timestamp: TimestampData
    member signature: felt # TODO should be bytes

end

# PartSetHeader is done
struct PartSetHeaderData:
    member total: felt # TODO should be uint64
    member hash: felt # TODO should be bytes

end

# BlockIDData is done
struct BlockIDData:
    member hash: felt # TODO needs to be bytes
    member part_set_header: PartSetHeaderData

end

# DurationData is done
struct DurationData:
    member Seconds: felt # TODO should be int64
    member nanos: felt # TODO should be int32
end


# TODO: implement signatures as an array of unknown length
struct CommitData:
    member height: felt #TODO replace with int64
    member round: felt #TODO replace with int32
    member block_id: BlockIDData # TODO implement BlockIDData
    # the following line should be a list of CommitSigData
    member signatures: CommitSigData # TODO implement CommitSigData
end

# ConsensusData is done
struct ConsensusData:
    member block: felt # TODO replace with uint64
    member app: felt # TODO replace with uint64

end

struct LightHeaderData:
    member version: ConsensusData # TODO maybe this needs to be a pointer
    member chain_id: felt # TODO replace with hash of string
    member height: felt # TODO replace with int64
    member time: TimestampData
    member last_block_id: BlockIDData
    member last_commit_hash: felt # TODO replace with bytes
    member data_hash: felt # TODO replace with bytes
    member validators_hash: felt # TODO replace with bytes
    member next_validators_hash: felt # TODO replace with bytes
    member consensus_hash: felt # TODO replace with bytes
    member app_hash: felt # TODO replace with bytes
    member last_results_hash: felt # TODO replace with bytes
    member proposer_address: felt # TODO replace with bytes
    
end

# Done
struct SignedHeaderData:
    member header: LightHeaderData
    member commit: CommitData
end

@external
func verifyAdjacent (
    trustedHeader: SignedHeaderData,
    untrustedHeader: SignedHeaderData
    # untrustedVals: ValidatorSetData,
    # trustingPeriod: DurationData,
    # currentTime: DurationData,
    # maxClockDrift: DurationData

    # the following res returns a 0 or 1 boolean
) -> (res: felt) :
    
    assert untrustedHeader.header.height = trustedHeader.header.height + 1
    return (1)
end 


