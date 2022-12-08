%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.hash import hash2
from src.hashing import hash_int128_array

@external
func test_hash_int128_array{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> () {
    alloc_locals;
    local num00;
    local num01;
    local num02;
    local exp0;

%{
import json
with open('../test_inputs/pedersen_test_array.json') as f:
    loaded = json.load(f)

ids.num00 = loaded[0]["Array"][0]
ids.num01 = loaded[0]["Array"][1]
ids.num02 = loaded[0]["Array"][2]
%}   
    
    let (local to_hash_array: felt*) = alloc();
    assert to_hash_array[0] = num00;
    assert to_hash_array[1] = num01;
    assert to_hash_array[2] = num02;

    let (local exp0: felt) = hash_int128_array(to_hash_array, 3);

    let (res_1: felt) = hash2{hash_ptr=pedersen_ptr}(0, num00);
    let (res_2: felt) = hash2{hash_ptr=pedersen_ptr}(res_1, num01);
    let (res_3: felt) = hash2{hash_ptr=pedersen_ptr}(res_2, num02);
    let (res_4: felt) = hash2{hash_ptr=pedersen_ptr}(res_3, 3);

    // This output is fed into tendermint tests.
    %{ print(ids.exp0) %}

    assert res_4 = exp0;
%{
new_json = loaded
new_json[0]['Expected'] = str(ids.exp0)
with open('../test_inputs/pedersen_test_array.json', 'w', encoding='utf-8') as f:
    json.dump(new_json, f, ensure_ascii=False, indent = 4)
    
%}
   return ();
}