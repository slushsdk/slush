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
    hash,
    hash_int128_array,
    hash_felt,
    hash_felt_array,
)
from src.merkle import get_split_point, leafHash, innerHash, merkleRootHash
from src.struct_hasher import (
    hashHeader,
    canonicalPartSetHeaderHasher,
    hashBlockID,
    hashCanonicalVoteNoTime,
)

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem

@external
func test_hash_int128_array_empty{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    alloc_locals;
    let (local to_hash_array: felt*) = alloc();

    let res_hash: felt = hash_int128_array(to_hash_array, 0);

    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(0, 0);

    // This output is fed into tendermint tests.
    %{ print(ids.res_hash) %}

    assert res_1 = res_hash;
    return ();
}

@external
func test_hash2{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    // import JSON with input data
    alloc_locals;
    local num00;
    local num01;
    local num10;
    local num11;
    local num20;
    local num21;
    local num30;
    local num31;
    local exp0;
    local exp1;
    local exp2;
    local exp3;
    %{
    import json
    with open('../test_inputs/hash_test_array.json') as f:
        loaded = json.load(f)

    ids.num00 = loaded[0]["Array"][0]
    ids.num01 = loaded[0]["Array"][1]

    ids.num10 = loaded[1]["Array"][0]
    ids.num11 = loaded[1]["Array"][1]
    
    ids.num20 = loaded[2]["Array"][0]
    ids.num21 = loaded[2]["Array"][1]
    
    ids.num30 = loaded[3]["Array"][0]
    ids.num31 = loaded[3]["Array"][1]
    %}
    // call hash2 on the imported data

    let (exp0: felt) = hash2{hash_ptr=pedersen_ptr}(num00,num01);
    let (exp1: felt) = hash2{hash_ptr=pedersen_ptr}(num10,num11);
    let (exp2: felt) = hash2{hash_ptr=pedersen_ptr}(num20,num21);
    let (exp3: felt) = hash2{hash_ptr=pedersen_ptr}(num30,num31);

    // assemble the new JSON with the output hash2 
    // print to file
    
    %{
new_json = loaded
new_json[0]['Expected'] = str(ids.exp0)
new_json[1]['Expected'] = str(ids.exp1)
new_json[2]['Expected'] = str(ids.exp2)
new_json[3]['Expected'] = str(ids.exp3)

with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    %}
    return ();
}


@external
func test_hash_felt{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    local num00;
    local exp0;

    //  import JSON with python
    %{
    import json
    with open('../test_inputs/hash_test_array.json') as f:
        loaded = json.load(f)

    ids.num00 = loaded[0]["Array"][0]
    %}
    // do the hashing
    let (exp0: felt) = hash_felt(num00);

    // assert exp0 = 208998628034825342117067982148086513282306647093844609550582231725359408128;
    // export JSON

    %{
    new_json = loaded
    new_json[4]['Expected'] = str(ids.exp0)

    with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
        json.dump(new_json, f, ensure_ascii=False, indent = 4)
    %} 

    return();

}


@external
func test_hash_felt_array{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    // create array of felts to be split and hashed
    alloc_locals;
    local num00;
    local num01;
    local num10;
    local num11;
    local num12;

    local num20;
    local num21;
    local num22;
    local num23;
    local num24;
    local num25;
    local num26;
    local num27;
    local num28;
    local num29;

    // local exp0;
    // local exp1;
    // local exp2;

    //  import JSON with python
    
    %{
import json
with open('../test_inputs/hash_test_array.json') as f:
        loaded = json.load(f)

ids.num00 = loaded[5]["Array"][0]
ids.num01 = loaded[5]["Array"][1]

ids.num10 = loaded[6]["Array"][0]
ids.num11 = loaded[6]["Array"][1]
ids.num12 = loaded[6]["Array"][2]
   
ids.num20 = loaded[7]["Array"][0]
ids.num21 = loaded[7]["Array"][1] 
ids.num22 = loaded[7]["Array"][2] 
ids.num23 = loaded[7]["Array"][3] 
ids.num24 = loaded[7]["Array"][4] 
ids.num25 = loaded[7]["Array"][5] 
ids.num26 = loaded[7]["Array"][6] 
ids.num27 = loaded[7]["Array"][7] 
ids.num28 = loaded[7]["Array"][8] 
ids.num29 = loaded[7]["Array"][9] 
    %}
    
    // ap+= 7;
    
    let (local to_hash_array0: felt*) = alloc();
    let (local to_hash_array1: felt*) = alloc();
    let (local to_hash_array2: felt*) = alloc();    
    
    assert to_hash_array0[0] = num00;
    assert to_hash_array0[1] = num01;
    
    assert to_hash_array1[0] = num10;
    assert to_hash_array1[1] = num11;
    assert to_hash_array1[2] = num12;
    
    assert to_hash_array2[0] = num20;
    assert to_hash_array2[1] = num21;
    assert to_hash_array2[2] = num22;
    assert to_hash_array2[3] = num23;
    assert to_hash_array2[4] = num24;
    assert to_hash_array2[5] = num25;
    assert to_hash_array2[6] = num26;
    assert to_hash_array2[7] = num27;
    assert to_hash_array2[8] = num28;
    assert to_hash_array2[9] = num29;
    // call the hash_array fn on this array
    // local exp0;
    let (local exp0: felt) = hash_felt_array(array_pointer=to_hash_array0, array_pointer_len=2);
    let (local exp1: felt) = hash_felt_array(array_pointer=to_hash_array1, array_pointer_len=3);
    let (local exp2: felt) = hash_felt_array(array_pointer=to_hash_array2, array_pointer_len=10);

    // To be fed into tendermint tests
    %{ print(ids.exp0) %}

    // check that this res_hash is the same as hashing the single felt by hand

    // let low_low3: felt = 104;

    // let low_low4: felt = 105;

    // let (res_hash7) = hash2{hash_ptr=pedersen_ptr}(0, low_low3);
    // let (res_hash8) = hash2{hash_ptr=pedersen_ptr}(res_hash7, low_low4);

    // let (res_hash_manual) = hash2{hash_ptr=pedersen_ptr}(res_hash8, 2);
    // assert res_hash_manual = res_hash_test;
    
    %{
new_json = loaded
#new_json[5]['Expected'] = str(0)
#new_json[6]['Expected'] = str(1)
#new_json[7]['Expected'] = str(2)
new_json[5]['Expected'] = str(ids.exp0)
new_json[6]['Expected'] = str(ids.exp1)
new_json[7]['Expected'] = str(ids.exp2)

with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    %}

    return ();
}

@external
func test_hash_test_case_0{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    // create array of felts to be split and hashed
    alloc_locals;
    local num00;
    local exp0;
    // here the JSON import is not doing any work, as it's an empty array

%{
import json
with open('../test_inputs/hash_test_array.json') as f:
    loaded = json.load(f)

#    ids.num00 = loaded[8]["Array"][0]
%}    

    let (local to_hash_array: felt*) = alloc();
    let to_hash_array_len = 0;

    // call the hash_array fn on this array

    let ( local exp0: felt) = hash(to_hash_array, to_hash_array_len);

    // To be fed into tendermint tests
    %{ print(ids.exp0) %}

    // check that this res_hash is the same as hashing the single felt by hand
    let (res_hash_manual) = hash2{hash_ptr=pedersen_ptr}(0, 0);

    assert res_hash_manual = exp0;
%{
new_json = loaded
new_json[8]['Expected'] = str(ids.exp0)
with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    
%}

  return ();
}

@external
func test_hash_test_case_1{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    // create array of felts to be split and hashed
    alloc_locals;
    local num00;
    local exp0;

%{
import json
with open('../test_inputs/hash_test_array.json') as f:
    loaded = json.load(f)

ids.num00 = loaded[9]["Array"][0]
%}  

    let (local to_hash_array: felt*) = alloc();
    assert to_hash_array[0] = num00;
    let to_hash_array_len = 1;

    // call the hash_array fn on this array

    let ( local exp0: felt) = hash(to_hash_array, to_hash_array_len);

    // To be fed into tendermint tests
    %{ print(ids.exp0) %}

    // check that this res_hash is the same as hashing the single felt by hand

    let (res_hash_manual) = hash_felt(104);
    assert res_hash_manual = exp0;

%{
new_json = loaded
new_json[9]['Expected'] = str(ids.exp0)
with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    
%}

    return ();
}

@external
func test_hash_test_case_2{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    // create array of felts to be split and hashed
    alloc_locals;
    local num00;
    local num01;
    local exp0;

%{
import json
with open('../test_inputs/hash_test_array.json') as f:
    loaded = json.load(f)

ids.num00 = loaded[10]["Array"][0]
ids.num01 = loaded[10]["Array"][1]
%}

    let (local to_hash_array: felt*) = alloc();
    assert to_hash_array[0] = num00;
    assert to_hash_array[1] = num01;
    let to_hash_array_len = 2;

    // call the hash_array fn on this array

    let (local exp0: felt) = hash(to_hash_array, to_hash_array_len);

    // To be fed into tendermint tests
    %{ print(ids.exp0) %}

    // check that this res_hash is the same as hashing the single felt by hand

    let (res_hash_manual) = hash_felt_array(to_hash_array, to_hash_array_len);
    assert res_hash_manual = exp0;

%{
new_json = loaded
new_json[10]['Expected'] = str(ids.exp0)
with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    
%}
    return ();
}

@external
func test_hash_test_case_3{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    // create array of felts to be split and hashed
    alloc_locals;
    
    local num20;
    local num21;
    local num22;
    local num23;
    local num24;
    local num25;
    local num26;
    local num27;
    local num28;
    local num29;

    local exp0;
    // local exp1;
    // local exp2;

    //  import JSON with python
    
    %{
import json
with open('../test_inputs/hash_test_array.json') as f:
        loaded = json.load(f)

ids.num20 = loaded[11]["Array"][0]
ids.num21 = loaded[11]["Array"][1] 
ids.num22 = loaded[11]["Array"][2] 
ids.num23 = loaded[11]["Array"][3] 
ids.num24 = loaded[11]["Array"][4] 
ids.num25 = loaded[11]["Array"][5] 
ids.num26 = loaded[11]["Array"][6] 
ids.num27 = loaded[11]["Array"][7] 
ids.num28 = loaded[11]["Array"][8] 
ids.num29 = loaded[11]["Array"][9] 
    %}    
    

    let (local to_hash_array2: felt*) = alloc();
    assert to_hash_array2[0] = num20;
    assert to_hash_array2[1] = num21;
    assert to_hash_array2[2] = num22;
    assert to_hash_array2[3] = num23;
    assert to_hash_array2[4] = num24;
    assert to_hash_array2[5] = num25;
    assert to_hash_array2[6] = num26;
    assert to_hash_array2[7] = num27;
    assert to_hash_array2[8] = num28;
    assert to_hash_array2[9] = num29;

    let to_hash_array_len = 10;

    // call the hash_array fn on this array

    let ( local exp0: felt )= hash(to_hash_array2, to_hash_array_len);

    // To be fed into tendermint tests
    %{ print(ids.exp0) %}

    // check that this res_hash is the same as hashing the single felt by hand

    let (res_hash_manual) = hash_felt_array(to_hash_array2, to_hash_array_len);
    assert res_hash_manual = exp0;
%{
new_json = loaded
new_json[11]['Expected'] = str(ids.exp0)
with open('../test_inputs/hash_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    
%}

    return ();
}
