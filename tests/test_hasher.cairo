%lang starknet
from src.main import (verifyNewHeaderAndVals, get_total_voting_power, voteSignBytes, verifySig, get_tallied_voting_power, verifyCommitLight, verifyAdjacent, verifyNonAdjacent)
from src.structs import (TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, BLOCK_ID_FLAG_UNKNOWN, BLOCK_ID_FLAG_ABSENT, BLOCK_ID_FLAG_COMMIT, BLOCK_ID_FLAG_NIL, MAX_TOTAL_VOTING_POWER, TimestampData, SignatureData, ChainID, CommitSigData, PartSetHeaderData, BlockIDData, DurationData, CommitSigDataArray, CommitData, CanonicalVoteData, ConsensusData, LightHeaderData, SignedHeaderData, ValidatorDataArray, PublicKeyData, ValidatorData, ValidatorSetData, FractionData )
from src.utils import (time_greater_than, isExpired, greater_than, recursive_comparison)
from src.hashing import ( hash_int64, hash_int64_array, hash_felt, hash_felt_array)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash)
from src.struct_hasher import ( hashHeader, canonicalPartSetHeaderHasher, blockIDHasher, hashCanonicalVoteNoTime)


from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem


func hasher{pedersen_ptr : HashBuiltin*}(a:felt, b:felt)->(res:felt):

    let (hash) = hash2{hash_ptr=pedersen_ptr}(a,b)
    %{print('ids.hash')%}
    %{print(ids.hash)%}
    return(hash)

end

@external
func test_hash{pedersen_ptr : HashBuiltin*}() -> (res:felt):

    let (res1) = hasher(1,2)
    %{print(ids.res1)%}
    return(res1)

end


@external
func test_psh_hasher{pedersen_ptr:HashBuiltin*}()->(res:felt):
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)
    let (res_psh) = canonicalPartSetHeaderHasher(part_set_header1)

    %{print(ids.res_psh)%}
    return(res_psh)
end

@external
func test_blockIDHasher{pedersen_ptr:HashBuiltin*}()->(res:felt):
    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)
    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)
    let (res_bidd) = blockIDHasher(block_id = blockid1)

    %{print(ids.res_bidd)%}
    return(res_bidd)
end

@external
func test_hashCanonicalVoteNoTime{pedersen_ptr:HashBuiltin*}()->(res:felt):
    alloc_locals
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 2)
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag( BlockIDFlag = 1)
    let time0 = TimestampData(nanos = 0)

    # create the comit content
    let signature_data: SignatureData = SignatureData(signature_r = 0, signature_s =1)

    local commitsig_Absent : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Absent, validators_address = 1,
    timestamp = time0, signature= signature_data)

    local commitsig_Commit : CommitSigData = CommitSigData(
    block_id_flag = Tendermint_BlockIDFLag_Commit, validators_address = 1,
    timestamp = time0, signature= signature_data)

    let (local commitsig1_pointer: CommitSigData*) =alloc()
    let(_,ap_commitsig) = get_fp_and_pc()
    let commitsig_fp= cast(ap_commitsig, CommitSigData*)
    assert commitsig1_pointer[0] = commitsig_Absent
    let(fp_commitsig1) = get_ap()
    assert commitsig1_pointer[1] = commitsig_Commit
    let(fp_commitsig2) = get_ap()
    assert commitsig1_pointer[2] = commitsig_Commit
    assert commitsig1_pointer[3] = commitsig_Commit

    let commitsig1_array = CommitSigDataArray(array = commitsig1_pointer, len = 4)


    # comit content created

    let part_set_header1 = PartSetHeaderData(total = 1, hash = 2)


    let blockid1 = BlockIDData(hash = 1, part_set_header = part_set_header1)

    let (local chain_id_ptr: felt*) =alloc()

    assert chain_id_ptr[0] = 1

    assert chain_id_ptr[1] = 2


    let chain_id1= ChainID(chain_id_array =chain_id_ptr , len = 2)
    # let comit1 = CommitData(height = 11100111, round = 1, block_id = blockid1,
    #     signatures = commitsig1_array)
    let CVData= CanonicalVoteData(TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType=1,
    height = 11100111, round = 1, block_id = blockid1,
    timestamp= time0, chain_id=chain_id1)
    let (res_hashCVNT) = hashCanonicalVoteNoTime(CVData= CVData)

    %{print(ids.res_hashCVNT)%}
    return(res_hashCVNT)
end