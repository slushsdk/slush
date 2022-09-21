
@external
func test_get_split_point{bitwise_ptr: BitwiseBuiltin*, range_check_ptr}() -> ():

    let res1: felt = get_split_point(5)
    assert res1 =4

    let res2: felt = get_split_point(2)
    assert res2 =2
    
    let res2: felt = get_split_point(25)
    assert res2 =16

    return()
end



func test_merkle_hash_complete_tree{range_check_ptr, pedersen_ptr : HashBuiltin*, hash_ptr : HashBuiltin*, bitwise_ptr: BitwiseBuiltin*}() -> ():
    alloc_locals
    let (node0 : felt) = hash_felt(6)
    let (node1 : felt) = hash_felt(11)
    let (node2 : felt) = hash_felt(40)
    let (node3 : felt) = hash_felt(69)

    let (local tree : felt*) = alloc()
    assert tree[0] = node0
    assert tree[1] = node1
    assert tree[2] = node2
    assert tree[3] = node3

    # with manual hashing
    let (node01 : felt) = hash2(node0, node1)
    let (node23 : felt) = hash2(node2, node3)
    let (node0123 : felt) = hash2(node01, node23)

    # with merkle function call
    let (node0123_m : felt) = merkleRootHash(tree, 0, 4)
    assert node0123 = node0123_m

    return ()
end

 #func test_merkle_hash_incomplete_tree() -> ():
 #    alloc_locals
 #    let (node0 : felt) = split_hash4(6)
 #    let (node1 : felt) = split_hash4(11)
 #    let (node2 : felt) = split_hash4(40)
 #    let (node3 : felt) = split_hash4(69)
 #
 #    let (local tree : felt) = alloc()
 #    assert tree[0] = node0
 #    assert tree[1] = node1
 #    assert tree[2] = node2
 #    assert tree[3] = node3
 #
 #    # with manual hashing
 #    let (node01 : felt) = hash2(node0, node1)
 #    let (node23 : felt) = hash2(node2, node3)
 #    let (node0123 : felt) = hash2(node01, node23)
 #
 #    # with merkle function call
 #    let (node0123_m : felt) = merkleRootHash(tree, 0, 4)
 #    assert node0123 = node0123_m
 #
 #    return ()
 #end
