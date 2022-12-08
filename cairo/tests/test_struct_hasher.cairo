%lang starknet
from src.main import (
    verifyNewHeaderAndVals,
    get_total_voting_power,
    voteSignBytes,
    verifySig,
    get_tallied_voting_power,
    verifyCommitLight,
    verifyAdjacent,
    verifyNonAdjacent,
)
from src.structs import (
    TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType,
    TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag,
    BLOCK_ID_FLAG_UNKNOWN,
    BLOCK_ID_FLAG_ABSENT,
    BLOCK_ID_FLAG_COMMIT,
    BLOCK_ID_FLAG_NIL,
    MAX_TOTAL_VOTING_POWER,
    TimestampData,
    SignatureData,
    ChainID,
    CommitSigData,
    PartSetHeaderData,
    BlockIDData,
    DurationData,
    CommitSigDataArray,
    CommitData,
    CanonicalVoteData,
    ConsensusData,
    LightHeaderData,
    SignedHeaderData,
    ValidatorDataArray,
    PublicKeyData,
    ValidatorData,
    ValidatorSetData,
    FractionData,
)
from src.utils import time_greater_than, isExpired, greater_than, recursive_comparison
from src.hashing import (
    hash_felt,
    hash_felt_array
)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash, )
from src.struct_hasher import (
    hashHeader,
    canonicalPartSetHeaderHasher,
    hashBlockID,
    hashCanonicalVoteNoTime,
    merkleRootHashVals,
    hashTime,
    )

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem

@external
func test_blockIDHasher{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    let part_set_header1 = PartSetHeaderData(total=1, hash=2);
    let blockid1 = BlockIDData(hash=1, part_set_header=part_set_header1);
    let (res_bidd) = hashBlockID(block_id=blockid1);

    %{ print(ids.res_bidd) %}
    return (res_bidd,);
}

@external
func test_hashCanonicalVoteNoTime{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    alloc_locals;
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=2
    );
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=1
    );

    // load input from json file
    local PSHTotal;
    local PSHHash;
    local CanonicalBlockIDHash;
    local Time;
    local MSGType;

    local Height;
    local Round;
    local ChainIDloaded;
    local ChainIDFelt;
    local Expected;
    %{
    import json
    with open('../test_inputs/hash_test_can_vote.json') as f:
        loaded = json.load(f)

    ids.PSHTotal = loaded['PSHTotal']
    ids.PSHHash = loaded['PSHHash']
    ids.CanonicalBlockIDHash = loaded['CanonicalBlockIDHash']
    ids.Time = loaded['Time']
    ids.MSGType = loaded['Type']
    ids.Height = loaded['Height']
    ids.Round = loaded['Round']
    ids.ChainIDFelt = loaded['ChainIDFelt']
    
    %}

    // comit content created
    let time0 = TimestampData(nanos=Time);

    let part_set_header1 = PartSetHeaderData(total = PSHTotal, hash=PSHHash);

    let blockid1 = BlockIDData(hash=CanonicalBlockIDHash, part_set_header=part_set_header1);

    let (local chain_id_ptr: felt*) = alloc();

    assert chain_id_ptr[0] = ChainIDFelt;

    let chain_id1 = ChainID(chain_id_array=chain_id_ptr, len=1);
    let CVData = CanonicalVoteData(
        TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType=MSGType,
        height=Height,
        round=Round,
        block_id=blockid1,
        timestamp=time0,
        chain_id=chain_id1,
    );
    %{print('blockid')%}
    // tempvar time0nanos = CVData.height;
    // %{print(ids.time0nanos)%}
    let (res_hash) = hashCanonicalVoteNoTime(CVData=CVData);

    // save the result to json file

    %{
new_json = loaded

new_json['Expected'] = str(ids.res_hash)


with open('../test_inputs/hash_test_can_vote.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    %}

    %{ print('ids.res_hash') %}
    %{ print(ids.res_hash) %}
    return (res_hash,);
}

@external
func test_psh_hasher{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    alloc_locals;

    local Total;
    local Hash;

    %{
    import json
    with open('../test_inputs/hash_test_cpsh.json') as f:
        loaded = json.load(f)

    ids.Total = loaded['Total']
    ids.Hash = loaded['Hash']
    %}

    // create CPSH and hash it
    let part_set_header1 = PartSetHeaderData(total=Total, hash=Hash);
    let (res_psh) = canonicalPartSetHeaderHasher(part_set_header1);


    %{
new_json = loaded
new_json['Expected'] = str(ids.res_psh)

with open('../test_inputs/hash_test_cpsh.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    %}


    %{ print("ids.res_psh") %}
    %{ print(ids.res_psh) %}
    return (res_psh,);
}


@external
func test_merkleRootHashVals{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*,}(
) {
    alloc_locals;
    // create validator array
    let (local ValidatorData_pointer0: ValidatorData*) = alloc();
    let public_key0: PublicKeyData = PublicKeyData(
        ecdsa=2018814482924085357616383108698434730223093418936929106356647082092697187097
    );
    let validator_data0: ValidatorData = ValidatorData(
        Address = 2830285380090611654456097681741309491500115890662641243882829676108909157038,
        pub_key=public_key0,
        voting_power=10,
        proposer_priority=0,
    );
    assert ValidatorData_pointer0[0] = validator_data0;

    let validator_array0: ValidatorDataArray = ValidatorDataArray(
        array=ValidatorData_pointer0, len=1
    );
    let validator_set0: ValidatorSetData = ValidatorSetData(
        validators=validator_array0, proposer=validator_data0, total_voting_power=10
    );

    let (res:felt) = merkleRootHashVals(validator_array0, 0, 1);
    // %{print("ids.res")%}
    // %{print(ids.res)%}
    return();
}


@external
func test_timehash{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*,}(
) {
    alloc_locals;
    local Time;

    %{
    import json
    with open('../test_inputs/hash_test_time.json') as f:
        loaded = json.load(f)
     
    ids.Time = loaded['Time']
    
    %}

    let time0 = TimestampData(nanos=Time);
    let (res:felt) = hashTime(time0);

    %{
    new_json = loaded
    new_json['Expected'] = str(ids.res)
    with open('../test_inputs/hash_test_time.json', 'w', encoding='utf-8') as f:
        json.dump(new_json, f, ensure_ascii=False, indent = 4)
    %}

    return();

}
