%lang starknet
from src.main import (verifyNewHeaderAndVals, get_total_voting_power, voteSignBytes, verifySig, get_tallied_voting_power, verifyCommitLight, verifyAdjacent, verifyNonAdjacent)
from src.structs import (TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSSignedMsgType, TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag, BLOCK_ID_FLAG_UNKNOWN, BLOCK_ID_FLAG_ABSENT, BLOCK_ID_FLAG_COMMIT, BLOCK_ID_FLAG_NIL, MAX_TOTAL_VOTING_POWER, TimestampData, SignatureData, ChainID, CommitSigData, PartSetHeaderData, BlockIDData, DurationData, CommitSigDataArray, CommitData, CanonicalVoteData, ConsensusData, LightHeaderData, SignedHeaderData, ValidatorDataArray, PublicKeyData, ValidatorData, ValidatorSetData, FractionData )
from src.utils import (time_greater_than, isExpired, greater_than, recursive_comparison)
from src.hashing import ( hash_int64, hash_int64_array, hash_felt, hash_felt_array)
from src.merkle import (get_split_point, leafHash, innerHash, merkleRootHash)
from src.struct_hasher import ( hashHeader, canonicalPartSetHeaderHasher, hashBlockID, hashCanonicalVoteNoTime)


from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn, split_felt, unsigned_div_rem
from starkware.cairo.common.signature import (verify_ecdsa_signature)
#from starkware.crypto.signature.signature import ( pedersen_hash, private_to_stark_key, sign)


@external
func test_verifySig{syscall_ptr: felt*,ecdsa_ptr: SignatureBuiltin*,  pedersen_ptr: HashBuiltin*, range_check_ptr}()->():
    alloc_locals
    let priv = 621985942509764716616923751397746736717180637362732023808823403073919878238
    let pubkey = PublicKeyData(ed25519 = 0, secp256k1 = 0, sr25519 = 0, ecdsa = 2630205952661076100278067785442586464608320854260474570987929663123950872221)
    # let pubkey2 = private_to_stark_key(priv)

    #%{print(id.pubkey)%}

    let val = ValidatorData(Address = 0, pub_key = pubkey, voting_power= 0, proposer_priority= 0 )
    
    let message = 8329030095893906201465693050266201662364576831283196587123454753936159886
    let signature = SignatureData(signature_r = 3260091926162606203766396237589078325776364930753843948833815498230926941681, signature_s = 2477874058515991563997172145462398723848358556819914618899699053933782735300)
    verifySig(val , message,  signature)

    

    return ()
end

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