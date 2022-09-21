

@external
func test_recursive_comparison{pedersen_ptr:HashBuiltin*}()->(res:felt):
    alloc_locals
    
       
    let (local chain_id_ptr_one: felt*) =alloc()   
    assert chain_id_ptr_one[0] = 1 
    assert chain_id_ptr_one[1] = 2
       
    let (local chain_id_ptr_two: felt*) =alloc()   
    assert chain_id_ptr_two[0] = 1 
    assert chain_id_ptr_two[1] = 2 

    recursive_comparison(chain_id_ptr_one, chain_id_ptr_two, 2)
    
    return(1)
end