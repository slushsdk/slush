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
from src.hashing import hash_int64, hash_int64_array, hash_felt, hash_felt_array, split_felt_to_64
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

// @external
func test_verifyAdjacent{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
}() -> () {
    let time0 = TimestampData(nanos=0);
    let time01 = TimestampData(nanos=1);
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=1
    );
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=2
    );
    alloc_locals;

    let signature_data: SignatureData = SignatureData(signature_r=0, signature_s=1);

    local commitsig_Absent: CommitSigData = CommitSigData(
        block_id_flag=Tendermint_BlockIDFLag_Absent, validators_address=1,
        timestamp=time0, signature=signature_data);

    local commitsig_Commit: CommitSigData = CommitSigData(
        block_id_flag=Tendermint_BlockIDFLag_Commit, validators_address=1,
        timestamp=time0, signature=signature_data);

    let (local commitsig1_pointer: CommitSigData*) = alloc();

    // tempvar commitsig1_pointer[0] = CommitSigData( block_id_flag = Tendermint_BlockIDFLag, validators_address = 1, timestamp = time0, signature = 1)
    assert commitsig1_pointer[0] = commitsig_Absent;

    assert commitsig1_pointer[1] = commitsig_Commit;
    assert commitsig1_pointer[2] = commitsig_Commit;
    assert commitsig1_pointer[3] = commitsig_Commit;

    let (local chain_id_ptr: felt*) = alloc();

    assert chain_id_ptr[0] = 1;

    assert chain_id_ptr[1] = 2;
    let chain_id1 = ChainID(chain_id_array=chain_id_ptr, len=2);

    let commitsig1_array = CommitSigDataArray(array=commitsig1_pointer, len=4);
    let consensus1 = ConsensusData(block=1, app=1);
    let part_set_header1 = PartSetHeaderData(total=1, hash=1);
    let blockid1 = BlockIDData(hash=1, part_set_header=part_set_header1);

    let header1 = LightHeaderData(
        version=consensus1,
        chain_id=chain_id1,
        height=11100111,
        time=time0,
        last_block_id=blockid1,
        last_commit_hash=1,
        data_hash=1,
        validators_hash=1,
        next_validators_hash=2,
        consensus_hash=3,
        app_hash=4,
        last_results_hash=5,
        evidence_hash=1,
        proposer_address=6,
    );

    let header2 = LightHeaderData(
        version=consensus1,
        chain_id=chain_id1,
        height=11100112,
        time=time01,
        last_block_id=blockid1,
        last_commit_hash=1,
        data_hash=1,
        validators_hash=1,
        next_validators_hash=2,
        consensus_hash=3,
        app_hash=4,
        last_results_hash=5,
        evidence_hash=1,
        proposer_address=6,
    );

    let comit1 = CommitData(
        height=11100111, round=1, block_id=blockid1, signatures=commitsig1_array
    );

    let comit2 = CommitData(
        height=11100112, round=1, block_id=blockid1, signatures=commitsig1_array
    );

    let trustedHeader1 = SignedHeaderData(header=header1, commit=comit1);
    let untrustedHeader1 = SignedHeaderData(header=header2, commit=comit2);

    let (local ValidatorData_pointer0: ValidatorData*) = alloc();
    let (fp_validators0, _) = get_fp_and_pc();
    let public_key0: PublicKeyData = PublicKeyData(ecdsa=3);
    let validator_data0: ValidatorData = ValidatorData(
        Address=1, pub_key=public_key0, voting_power=2, proposer_priority=3
    );
    assert ValidatorData_pointer0[0] = validator_data0;
    assert ValidatorData_pointer0[1] = validator_data0;
    assert ValidatorData_pointer0[2] = validator_data0;
    assert ValidatorData_pointer0[3] = validator_data0;

    let validator_array0: ValidatorDataArray = ValidatorDataArray(
        array=ValidatorData_pointer0, len=4
    );
    let validator_set0: ValidatorSetData = ValidatorSetData(
        validators=validator_array0, proposer=validator_data0, total_voting_power=3
    );
    // verifyAdjacent{ecdsa_ptr: ecdsa_ptr}(trustedHeader= trustedHeader1, untrustedHeader= untrustedHeader1, untrustedVals=validator_set0,
    // verifyAdjacent(trustedHeader= trustedHeader1, untrustedHeader= untrustedHeader1, untrustedVals=validator_set0,
    // trustingPeriod = trustingPeriod, currentTime = currentTime2, maxClockDrift = maxClockDrift)

    // TODO write test for verifyNewHeaderAndVals

    // test verifyCommitLight
    // create inputs for verifyCommitLight function
    // PrivateKeyData
    let public_key1: PublicKeyData = PublicKeyData(ecdsa=3);
    let validator_data1: ValidatorData = ValidatorData(
        Address=1, pub_key=public_key1, voting_power=2, proposer_priority=3
    );

    let (local ValidatorData_pointer: ValidatorData*) = alloc();
    assert ValidatorData_pointer[0] = validator_data1;
    assert ValidatorData_pointer[1] = validator_data1;
    assert ValidatorData_pointer[2] = validator_data1;
    assert ValidatorData_pointer[3] = validator_data1;

    let validator_array: ValidatorDataArray = ValidatorDataArray(
        array=ValidatorData_pointer, len=4
    );

    let validator_set: ValidatorSetData = ValidatorSetData(
        validators=validator_array, proposer=validator_data1, total_voting_power=3
    );

    // verifyCommitLight(vals = validator_set, chainID= 1, blockID = blockid1, height= 11100111, commit = comit1)

    // test get_tallied_voting_power recurive function for adding up voting power

    // use
    // commit comit1
    //
    let (all_votes: felt) = get_tallied_voting_power(
        counter=0,
        commit=comit1,
        signatures_len=4,
        signatures=commitsig1_pointer,
        validators_len=4,
        validators=ValidatorData_pointer,
        chain_id=chain_id1,
    );
    let (total_voting_power: felt) = get_total_voting_power(
        validators_len=4, validators=ValidatorData_pointer
    );
    %{ print("ids.all_votes") %}
    %{ print(ids.commitsig1_pointer) %}
    %{ print(ids.all_votes) %}
    assert all_votes = 6;
    assert total_voting_power = 8;

    // call verifyCommitLight
    let blockid2 = BlockIDData(hash=1, part_set_header=part_set_header1);

    let valsInstance: ValidatorSetData = ValidatorSetData(
        validators=validator_array, proposer=validator_data1, total_voting_power=total_voting_power
    );
    verifyCommitLight(
        vals=valsInstance, chain_id=chain_id1, blockID=blockid2, height=11100111, commit=comit1
    );

    return ();
}

// @external
func test_vtime_comparision{
    range_check_ptr, pedersen_ptr: HashBuiltin*, ecdsa_ptr: SignatureBuiltin*
}() -> () {
    // test whether the time comparison works

    let time1 = TimestampData(nanos=9);
    let time2 = TimestampData(nanos=10);
    let time3 = TimestampData(nanos=11);

    let time4 = TimestampData(nanos=9);
    let time5 = TimestampData(nanos=10);
    let time6 = TimestampData(nanos=11);

    let time7 = TimestampData(nanos=9);
    let time8 = TimestampData(nanos=10);
    let time9 = TimestampData(nanos=11);

    let (time55) = time_greater_than(time5, time5);
    assert time55 = 0;

    let (time54) = time_greater_than(time5, time4);
    assert time54 = 1;

    let (time56) = time_greater_than(time5, time6);
    assert time56 = 0;

    let (time51) = time_greater_than(time5, time1);
    assert time51 = 1;

    let (time52) = time_greater_than(time5, time2);
    assert time52 = 0;

    let (time57) = time_greater_than(time5, time7);
    assert time57 = 1;

    let (time59) = time_greater_than(time5, time9);
    assert time59 = 0;

    // test whether the time comparison works
    let trustingPeriod = DurationData(nanos=9);
    let currentTime = DurationData(nanos=10);
    let maxClockDrift = DurationData(nanos=10);

    // Todo get an appropriate trustedheader1 here (this was copiedfrom verifyNewHeaderAndVals)
    // let (expired: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime)

    // assert expired = 1

    let currentTime2 = DurationData(nanos=5);

    // let (expired2: felt) = isExpired(trustedHeader1, trustingPeriod, currentTime2)

    // assert expired2 = 0

    return ();
}

// @external
func test_voteSignBytes{pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res: felt) {
    alloc_locals;
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=2
    );
    let Tendermint_BlockIDFLag_Absent = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=1
    );
    let time0 = TimestampData(nanos=0);
    let time1 = TimestampData(nanos=0);

    // create the comit content
    let signature_data: SignatureData = SignatureData(signature_r=0, signature_s=1);

    local commitsig_Absent: CommitSigData = CommitSigData(
        block_id_flag=Tendermint_BlockIDFLag_Absent, validators_address=1,
        timestamp=time0, signature=signature_data);

    local commitsig_Commit: CommitSigData = CommitSigData(
        block_id_flag=Tendermint_BlockIDFLag_Commit, validators_address=1,
        timestamp=time1, signature=signature_data);

    let (local commitsig1_pointer: CommitSigData*) = alloc();
    let (_, ap_commitsig) = get_fp_and_pc();
    let commitsig_fp = cast(ap_commitsig, CommitSigData*);
    assert commitsig1_pointer[0] = commitsig_Absent;
    let (fp_commitsig1) = get_ap();
    assert commitsig1_pointer[1] = commitsig_Commit;
    let (fp_commitsig2) = get_ap();
    assert commitsig1_pointer[2] = commitsig_Commit;
    assert commitsig1_pointer[3] = commitsig_Commit;

    let commitsig1_array = CommitSigDataArray(array=commitsig1_pointer, len=4);

    // comit content created

    let part_set_header1 = PartSetHeaderData(total=1, hash=2);

    let blockid1 = BlockIDData(hash=1, part_set_header=part_set_header1);
    let comit1 = CommitData(
        height=11100111, round=1, block_id=blockid1, signatures=commitsig1_array
    );

    let (local chain_id_ptr: felt*) = alloc();

    assert chain_id_ptr[0] = 1;

    assert chain_id_ptr[1] = 2;
    let chain_id1 = ChainID(chain_id_array=chain_id_ptr, len=2);

    let (timestamp1, res_hash1) = voteSignBytes(counter=1, commit=comit1, chain_id=chain_id1);

    %{ print('ids.res_hash1') %}
    %{ print(ids.res_hash1) %}
    let (timestamp2, res_hash2) = voteSignBytes(counter=0, commit=comit1, chain_id=chain_id1);

    %{ print(ids.res_hash2) %}
    return (res_hash1,);
}

@external
func test_real_data{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ecdsa_ptr: SignatureBuiltin*,
}() -> () {
    alloc_locals;
    let (local chain_id_ptr: felt*) = alloc();
    assert chain_id_ptr[0] = 116;
    assert chain_id_ptr[1] = 7310314358442582377;
    assert chain_id_ptr[2] = 7939082473277174873;
    let chain_id1 = ChainID(chain_id_array=chain_id_ptr, len=3);

    // create the header
    // chain_id = chain_id1 is a placeholder
    let header1_trusted: LightHeaderData = LightHeaderData(
        version=ConsensusData(block=11, app=1),
        chain_id=chain_id1,
        height=2,
        time=TimestampData(nanos=1665753871520445159),
        last_block_id=BlockIDData(hash=2606409042684652237028761825612341298588373841266340846590208831812555967679,
        part_set_header=PartSetHeaderData(total=1,
            hash=3000838125350084652609540693524514269948277526780094801048010237669338709953)),
        last_commit_hash=1931616577660260768497627594988710925560949687119466413940080031015097594698,
        data_hash=2089986280348253421170679821480865132823066470938446095505822317253594081284,
        validators_hash=2831012649517925635638083284349758092553206116379646415063645608642406529898,
        next_validators_hash=2831012649517925635638083284349758092553206116379646415063645608642406529898,
        consensus_hash=2132461975834504200398180281070409533541683498016798668455504133351250391630,
        app_hash=0,
        last_results_hash=2089986280348253421170679821480865132823066470938446095505822317253594081284,
        evidence_hash=2089986280348253421170679821480865132823066470938446095505822317253594081284,
        proposer_address=335674479734934146889037038263903380498452542860978104900782795296756624142,
    );

    // create commit
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=2
    );

    let signature_data_trusted: SignatureData = SignatureData(
        signature_r=1834131662309943167060654729634590738983734585222746799362362058903754262332,
        signature_s=1745065597501682152537867859965459308365142243262023073853228716084356784546,
    );

    local commitsig_Absent_trusted: CommitSigData = CommitSigData(
        block_id_flag=Tendermint_BlockIDFLag_Commit, validators_address=335674479734934146889037038263903380498452542860978104900782795296756624142,
        timestamp=TimestampData(nanos=1665753877127453388), signature=signature_data_trusted);

    let (local commitsig1_pointer_trusted: CommitSigData*) = alloc();
    assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted;
    let commitsig1_array_trusted = CommitSigDataArray(array=commitsig1_pointer_trusted, len=1);

    let commit1_trusted: CommitData = CommitData(
        height=2,
        round=0,
        block_id=BlockIDData(
        hash=2059766791315474971233242291515003944317013849850428055013818287621749261948,
        part_set_header=PartSetHeaderData(total=1, hash=1308036548029847327855861229891709942163426033933946107172305588954015556391)),
        signatures=commitsig1_array_trusted,
    );

    // create the header from these two
    let trusted_header: SignedHeaderData = SignedHeaderData(
        header=header1_trusted, commit=commit1_trusted
    );

    // create the header
    // chain_id = chain_id1 is a placeholder
    let header1_trusted: LightHeaderData = LightHeaderData(
        version=ConsensusData(block=11, app=1),
        chain_id=chain_id1,
        height=3,
        time=TimestampData(nanos=1665753884507525850),
        last_block_id=BlockIDData(hash=2059766791315474971233242291515003944317013849850428055013818287621749261948,
        part_set_header=PartSetHeaderData(total=1,
            hash=1308036548029847327855861229891709942163426033933946107172305588954015556391)),
        last_commit_hash=465267704775716075860689654059997816995530962997902813659991924419196233437,
        data_hash=2089986280348253421170679821480865132823066470938446095505822317253594081284,
        validators_hash=2831012649517925635638083284349758092553206116379646415063645608642406529898,
        next_validators_hash=2831012649517925635638083284349758092553206116379646415063645608642406529898,
        consensus_hash=2132461975834504200398180281070409533541683498016798668455504133351250391630,
        app_hash=0,
        last_results_hash=2089986280348253421170679821480865132823066470938446095505822317253594081284,
        evidence_hash=2089986280348253421170679821480865132823066470938446095505822317253594081284,
        proposer_address=335674479734934146889037038263903380498452542860978104900782795296756624142,
    );

    // create commit
    let Tendermint_BlockIDFLag_Commit = TENDERMINTLIGHT_PROTO_GLOBAL_ENUMSBlockIDFlag(
        BlockIDFlag=2
    );

    let signature_data_trusted: SignatureData = SignatureData(
        signature_r=3605504498823257379762570133327870210455706278164450482388963404778814325454,
        signature_s=3133371732092557530256163168714261110099475276750495027673839161202089731597,
    );

    local commitsig_Absent_trusted: CommitSigData = CommitSigData(
        block_id_flag=Tendermint_BlockIDFLag_Commit, validators_address=335674479734934146889037038263903380498452542860978104900782795296756624142,
        timestamp=TimestampData(nanos=1665753889554053779), signature=signature_data_trusted);

    let (local commitsig1_pointer_trusted: CommitSigData*) = alloc();
    assert commitsig1_pointer_trusted[0] = commitsig_Absent_trusted;
    let commitsig1_array_trusted = CommitSigDataArray(array=commitsig1_pointer_trusted, len=1);

    let commit1_trusted: CommitData = CommitData(
        height=3,
        round=0,
        block_id=BlockIDData(
        hash=490484232464039218793463646794795012959740951355156173400258415888395419419,
        part_set_header=PartSetHeaderData(total=1, hash=1680373902317584836581677072736116216148431538470704822243182371928708897588)),
        signatures=commitsig1_array_trusted,
    );

    // create the header from these two
    let untrusted_header: SignedHeaderData = SignedHeaderData(
        header=header1_trusted, commit=commit1_trusted
    );

    // create validator array
    let (local ValidatorData_pointer0: ValidatorData*) = alloc();
    let public_key0: PublicKeyData = PublicKeyData(
        ecdsa=3334500756028199475433036722527134417926233723147766471089429384364098171865
    );
    let validator_data0: ValidatorData = ValidatorData(
        Address=335674479734934146889037038263903380498452542860978104900782795296756624142,
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
    let currentTime2 = DurationData(nanos=1665753884507526850);
    let maxClockDrift = DurationData(nanos=10);
    let trustingPeriod = DurationData(nanos=99999999999999999999);

    verifyAdjacent(
        trustedHeader=trusted_header,
        untrustedHeader=untrusted_header,
        untrustedVals=validator_set0,
        trustingPeriod=trustingPeriod,
        currentTime=currentTime2,
        maxClockDrift=maxClockDrift,
    );

    return ();
}
