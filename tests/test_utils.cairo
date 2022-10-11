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

#imported signature from https://www.cairo-lang.org/docs/hello_starknet/signature_verification.html?highlight=signature#interacting-with-the-contract
@external
func test_verifySig{syscall_ptr: felt*,ecdsa_ptr: SignatureBuiltin*,  pedersen_ptr: HashBuiltin*, range_check_ptr}()->():
    alloc_locals
    let priv = 621985942509764716616923751397746736717180637362732023808823403073919878238
    #let pubkey = PublicKeyData( ecdsa = 2630205952661076100278067785442586464608320854260474570987929663123950872221)
    let pubkey = PublicKeyData( ecdsa = 1628448741648245036800002906075225705100596136133912895015035902954123957052)

    # let pubkey2 = private_to_stark_key(priv)

    let val = ValidatorData(Address = 0, pub_key = pubkey, voting_power= 0, proposer_priority= 0 )
    
    # let message = 8329030095893906201465693050266201662364576831283196587123454753936159886
    # let signature = SignatureData(signature_r = 3260091926162606203766396237589078325776364930753843948833815498230926941681, signature_s = 2477874058515991563997172145462398723848358556819914618899699053933782735300)
    let message = 2145928028330445730928899764978337236302436665109337681432022680924515407233
    let signature = SignatureData(signature_r = 1225578735933442828068102633747590437426782890965066746429241472187377583468, signature_s = 3568809569741913715045370357918125425757114920266578211811626257903121825123)
    
    
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

@external
func test_get_total_voting_power{pedersen_ptr:HashBuiltin*, range_check_ptr}()->(res:felt):
    alloc_locals
    
    let pub_key : PublicKeyData = PublicKeyData(ecdsa = 0)
    let validator_data0 :ValidatorData=  ValidatorData(Address=0, pub_key= pub_key, voting_power = 1, proposer_priority =0)
    let validator_data1 :ValidatorData=  ValidatorData(Address=0, pub_key= pub_key, voting_power = 2, proposer_priority =0)
    let validator_data2 :ValidatorData=  ValidatorData(Address=0, pub_key= pub_key, voting_power = 3, proposer_priority =0)


    let (local ValidatorData_pointer: ValidatorData*) =alloc()
    
    assert ValidatorData_pointer[0]=validator_data0
    assert ValidatorData_pointer[1]=validator_data1
    assert ValidatorData_pointer[2]=validator_data2


    let (res : felt)= get_total_voting_power(3, ValidatorData_pointer)
    assert res =6

    return(1)
end