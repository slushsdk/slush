package state_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	dbm "github.com/tendermint/tm-db"

	abciclient "github.com/tendermint/tendermint/abci/client"
	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/crypto/stark"
	"github.com/tendermint/tendermint/crypto/tmhash"
	mmock "github.com/tendermint/tendermint/internal/mempool/mock"
	"github.com/tendermint/tendermint/internal/proxy"
	sm "github.com/tendermint/tendermint/internal/state"
	"github.com/tendermint/tendermint/internal/state/mocks"
	sf "github.com/tendermint/tendermint/internal/state/test/factory"
	"github.com/tendermint/tendermint/internal/store"
	"github.com/tendermint/tendermint/libs/log"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmtime "github.com/tendermint/tendermint/libs/time"
	"github.com/tendermint/tendermint/types"
	"github.com/tendermint/tendermint/version"
)

var (
	chainID             = "execution_chain"
	testPartSize uint32 = 65536
)

func TestApplyBlock(t *testing.T) {
	app := &testApp{}
	cc := abciclient.NewLocalCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.Nil(t, err)
	defer proxyApp.Stop() //nolint:errcheck // ignore for tests

	state, stateDB, _ := makeState(1, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(),
		mmock.Mempool{}, sm.EmptyEvidencePool{}, blockStore)

	block := sf.MakeBlock(state, 1, new(types.Commit))
	blockID := types.BlockID{Hash: block.Hash(), PartSetHeader: block.MakePartSet(testPartSize).Header()}

	state, err = blockExec.ApplyBlock(state, blockID, block)
	require.Nil(t, err)

	// TODO check state and mempool
	assert.EqualValues(t, 1, state.Version.Consensus.App, "App version wasn't updated")
}

// TestBeginBlockValidators ensures we send absent validators list.
func TestBeginBlockValidators(t *testing.T) {
	app := &testApp{}
	cc := abciclient.NewLocalCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.Nil(t, err)
	defer proxyApp.Stop() //nolint:errcheck // no need to check error again

	state, stateDB, _ := makeState(2, 2)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})

	prevHash := state.LastBlockID.Hash
	prevParts := types.PartSetHeader{}
	prevBlockID := types.BlockID{Hash: prevHash, PartSetHeader: prevParts}

	var (
		now        = tmtime.Now()
		commitSig0 = types.NewCommitSigForBlock(
			[]byte("Signature1"),
			state.Validators.Validators[0].Address,
			now)
		commitSig1 = types.NewCommitSigForBlock(
			[]byte("Signature2"),
			state.Validators.Validators[1].Address,
			now)
		absentSig = types.NewCommitSigAbsent()
	)

	testCases := []struct {
		desc                     string
		lastCommitSigs           []types.CommitSig
		expectedAbsentValidators []int
	}{
		{"none absent", []types.CommitSig{commitSig0, commitSig1}, []int{}},
		{"one absent", []types.CommitSig{commitSig0, absentSig}, []int{1}},
		{"multiple absent", []types.CommitSig{absentSig, absentSig}, []int{0, 1}},
	}

	for _, tc := range testCases {
		lastCommit := types.NewCommit(1, 0, prevBlockID, tc.lastCommitSigs)

		// block for height 2
		block := sf.MakeBlock(state, 2, lastCommit)

		_, err = sm.ExecCommitBlock(nil, proxyApp.Consensus(), block, log.TestingLogger(), stateStore, 1, state)
		require.Nil(t, err, tc.desc)

		// -> app receives a list of validators with a bool indicating if they signed
		ctr := 0
		for i, v := range app.CommitVotes {
			if ctr < len(tc.expectedAbsentValidators) &&
				tc.expectedAbsentValidators[ctr] == i {

				assert.False(t, v.SignedLastBlock)
				ctr++
			} else {
				assert.True(t, v.SignedLastBlock)
			}
		}
	}
}

// TestBeginBlockByzantineValidators ensures we send byzantine validators list.
func TestBeginBlockByzantineValidators(t *testing.T) {
	app := &testApp{}
	cc := abciclient.NewLocalCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.Nil(t, err)
	defer proxyApp.Stop() //nolint:errcheck // ignore for tests

	state, stateDB, privVals := makeState(1, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})

	defaultEvidenceTime := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	privVal := privVals[state.Validators.Validators[0].Address.String()]
	blockID := makeBlockID([]byte("headerhash"), 1000, []byte("partshash"))
	header := &types.Header{
		Version:            version.Consensus{Block: version.BlockProtocol, App: 1},
		ChainID:            state.ChainID,
		Height:             10,
		Time:               defaultEvidenceTime,
		LastBlockID:        blockID,
		LastCommitHash:     tmrand.FeltBytes(crypto.HashSize),
		DataHash:           tmrand.FeltBytes(crypto.HashSize),
		ValidatorsHash:     state.Validators.Hash(),
		NextValidatorsHash: state.Validators.Hash(),
		ConsensusHash:      tmrand.FeltBytes(crypto.HashSize),
		AppHash:            tmrand.FeltBytes(crypto.HashSize),
		LastResultsHash:    tmrand.FeltBytes(crypto.HashSize),
		EvidenceHash:       tmrand.FeltBytes(crypto.HashSize),
		ProposerAddress:    tmrand.FeltBytes(crypto.AddressSize),
	}

	// we don't need to worry about validating the evidence as long as they pass validate basic
	dve := types.NewMockDuplicateVoteEvidenceWithValidator(3, defaultEvidenceTime, privVal, state.ChainID)
	dve.ValidatorPower = 1000
	lcae := &types.LightClientAttackEvidence{
		ConflictingBlock: &types.LightBlock{
			SignedHeader: &types.SignedHeader{
				Header: header,
				Commit: types.NewCommit(10, 0, makeBlockID(header.Hash(), 100, []byte("partshash")), []types.CommitSig{{
					BlockIDFlag:      types.BlockIDFlagNil,
					ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
					Timestamp:        defaultEvidenceTime,
					Signature:        crypto.CRandBytes(types.MaxSignatureSize),
				}}),
			},
			ValidatorSet: state.Validators,
		},
		CommonHeight:        8,
		ByzantineValidators: []*types.Validator{state.Validators.Validators[0]},
		TotalVotingPower:    12,
		Timestamp:           defaultEvidenceTime,
	}

	ev := []types.Evidence{dve, lcae}

	abciEv := []abci.Evidence{
		{
			Type:             abci.EvidenceType_DUPLICATE_VOTE,
			Height:           3,
			Time:             defaultEvidenceTime,
			Validator:        types.TM2PB.Validator(state.Validators.Validators[0]),
			TotalVotingPower: 10,
		},
		{
			Type:             abci.EvidenceType_LIGHT_CLIENT_ATTACK,
			Height:           8,
			Time:             defaultEvidenceTime,
			Validator:        types.TM2PB.Validator(state.Validators.Validators[0]),
			TotalVotingPower: 12,
		},
	}

	evpool := &mocks.EvidencePool{}
	evpool.On("PendingEvidence", mock.AnythingOfType("int64")).Return(ev, int64(100))
	evpool.On("Update", mock.AnythingOfType("state.State"), mock.AnythingOfType("types.EvidenceList")).Return()
	evpool.On("CheckEvidence", mock.AnythingOfType("types.EvidenceList")).Return(nil)

	blockStore := store.NewBlockStore(dbm.NewMemDB())

	blockExec := sm.NewBlockExecutor(stateStore, log.TestingLogger(), proxyApp.Consensus(),
		mmock.Mempool{}, evpool, blockStore)

	block := sf.MakeBlock(state, 1, new(types.Commit))
	block.Evidence = types.EvidenceData{Evidence: ev}
	block.Header.EvidenceHash = block.Evidence.Hash()
	blockID = types.BlockID{Hash: block.Hash(), PartSetHeader: block.MakePartSet(testPartSize).Header()}

	_, err = blockExec.ApplyBlock(state, blockID, block)
	require.Nil(t, err)

	// TODO check state and mempool
	assert.Equal(t, abciEv, app.ByzantineValidators)
}

func TestValidateValidatorUpdates(t *testing.T) {
	pubkey1 := stark.GenPrivKey().PubKey()
	pubkey2 := stark.GenPrivKey().PubKey()
	pk1, err := encoding.PubKeyToProto(pubkey1)
	assert.NoError(t, err)
	pk2, err := encoding.PubKeyToProto(pubkey2)
	assert.NoError(t, err)

	defaultValidatorParams := types.ValidatorParams{PubKeyTypes: []string{types.ABCIPubKeyTypeStark}}

	testCases := []struct {
		name string

		abciUpdates     []abci.ValidatorUpdate
		validatorParams types.ValidatorParams

		shouldErr bool
	}{
		{
			"adding a validator is OK",
			[]abci.ValidatorUpdate{{PubKey: pk2, Power: 20}},
			defaultValidatorParams,
			false,
		},
		{
			"updating a validator is OK",
			[]abci.ValidatorUpdate{{PubKey: pk1, Power: 20}},
			defaultValidatorParams,
			false,
		},
		{
			"removing a validator is OK",
			[]abci.ValidatorUpdate{{PubKey: pk2, Power: 0}},
			defaultValidatorParams,
			false,
		},
		{
			"adding a validator with negative power results in error",
			[]abci.ValidatorUpdate{{PubKey: pk2, Power: -100}},
			defaultValidatorParams,
			true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := sm.ValidateValidatorUpdates(tc.abciUpdates, tc.validatorParams)
			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUpdateValidators(t *testing.T) {
	pubkey1 := stark.GenPrivKey().PubKey()
	val1 := types.NewValidator(pubkey1, 10)
	pubkey2 := stark.GenPrivKey().PubKey()
	val2 := types.NewValidator(pubkey2, 20)

	pk, err := encoding.PubKeyToProto(pubkey1)
	require.NoError(t, err)
	pk2, err := encoding.PubKeyToProto(pubkey2)
	require.NoError(t, err)

	testCases := []struct {
		name string

		currentSet  *types.ValidatorSet
		abciUpdates []abci.ValidatorUpdate

		resultingSet *types.ValidatorSet
		shouldErr    bool
	}{
		{
			"adding a validator is OK",
			types.NewValidatorSet([]*types.Validator{val1}),
			[]abci.ValidatorUpdate{{PubKey: pk2, Power: 20}},
			types.NewValidatorSet([]*types.Validator{val1, val2}),
			false,
		},
		{
			"updating a validator is OK",
			types.NewValidatorSet([]*types.Validator{val1}),
			[]abci.ValidatorUpdate{{PubKey: pk, Power: 20}},
			types.NewValidatorSet([]*types.Validator{types.NewValidator(pubkey1, 20)}),
			false,
		},
		{
			"removing a validator is OK",
			types.NewValidatorSet([]*types.Validator{val1, val2}),
			[]abci.ValidatorUpdate{{PubKey: pk2, Power: 0}},
			types.NewValidatorSet([]*types.Validator{val1}),
			false,
		},
		{
			"removing a non-existing validator results in error",
			types.NewValidatorSet([]*types.Validator{val1}),
			[]abci.ValidatorUpdate{{PubKey: pk2, Power: 0}},
			types.NewValidatorSet([]*types.Validator{val1}),
			true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			updates, err := types.PB2TM.ValidatorUpdates(tc.abciUpdates)
			assert.NoError(t, err)
			err = tc.currentSet.UpdateWithChangeSet(updates)
			if tc.shouldErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				require.Equal(t, tc.resultingSet.Size(), tc.currentSet.Size())

				assert.Equal(t, tc.resultingSet.TotalVotingPower(), tc.currentSet.TotalVotingPower())

				assert.Equal(t, tc.resultingSet.Validators[0].Address, tc.currentSet.Validators[0].Address)
				if tc.resultingSet.Size() > 1 {
					assert.Equal(t, tc.resultingSet.Validators[1].Address, tc.currentSet.Validators[1].Address)
				}
			}
		})
	}
}

// TestEndBlockValidatorUpdates ensures we update validator set and send an event.
func TestEndBlockValidatorUpdates(t *testing.T) {
	app := &testApp{}
	cc := abciclient.NewLocalCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.Nil(t, err)
	defer proxyApp.Stop() //nolint:errcheck // ignore for tests

	state, stateDB, _ := makeState(1, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})
	blockStore := store.NewBlockStore(dbm.NewMemDB())

	blockExec := sm.NewBlockExecutor(
		stateStore,
		log.TestingLogger(),
		proxyApp.Consensus(),
		mmock.Mempool{},
		sm.EmptyEvidencePool{},
		blockStore,
	)

	eventBus := types.NewEventBus()
	err = eventBus.Start()
	require.NoError(t, err)
	defer eventBus.Stop() //nolint:errcheck // ignore for tests

	blockExec.SetEventBus(eventBus)

	updatesSub, err := eventBus.Subscribe(
		context.Background(),
		"TestEndBlockValidatorUpdates",
		types.EventQueryValidatorSetUpdates,
	)
	require.NoError(t, err)

	block := sf.MakeBlock(state, 1, new(types.Commit))
	blockID := types.BlockID{Hash: block.Hash(), PartSetHeader: block.MakePartSet(testPartSize).Header()}

	pubkey := stark.GenPrivKey().PubKey()
	pk, err := encoding.PubKeyToProto(pubkey)
	require.NoError(t, err)
	app.ValidatorUpdates = []abci.ValidatorUpdate{
		{PubKey: pk, Power: 10},
	}

	state, err = blockExec.ApplyBlock(state, blockID, block)
	require.Nil(t, err)
	// test new validator was added to NextValidators
	if assert.Equal(t, state.Validators.Size()+1, state.NextValidators.Size()) {
		idx, _ := state.NextValidators.GetByAddress(pubkey.Address())
		if idx < 0 {
			t.Fatalf("can't find address %v in the set %v", pubkey.Address(), state.NextValidators)
		}
	}

	// test we threw an event
	select {
	case msg := <-updatesSub.Out():
		event, ok := msg.Data().(types.EventDataValidatorSetUpdates)
		require.True(t, ok, "Expected event of type EventDataValidatorSetUpdates, got %T", msg.Data())
		if assert.NotEmpty(t, event.ValidatorUpdates) {
			assert.Equal(t, pubkey, event.ValidatorUpdates[0].PubKey)
			assert.EqualValues(t, 10, event.ValidatorUpdates[0].VotingPower)
		}
	case <-updatesSub.Canceled():
		t.Fatalf("updatesSub was canceled (reason: %v)", updatesSub.Err())
	case <-time.After(1 * time.Second):
		t.Fatal("Did not receive EventValidatorSetUpdates within 1 sec.")
	}
}

// TestEndBlockValidatorUpdatesResultingInEmptySet checks that processing validator updates that
// would result in empty set causes no panic, an error is raised and NextValidators is not updated
func TestEndBlockValidatorUpdatesResultingInEmptySet(t *testing.T) {
	app := &testApp{}
	cc := abciclient.NewLocalCreator(app)
	proxyApp := proxy.NewAppConns(cc, proxy.NopMetrics())
	err := proxyApp.Start()
	require.Nil(t, err)
	defer proxyApp.Stop() //nolint:errcheck // ignore for tests

	state, stateDB, _ := makeState(1, 1)
	stateStore := sm.NewStore(stateDB, sm.StoreOptions{
		DiscardABCIResponses: false,
	})
	blockStore := store.NewBlockStore(dbm.NewMemDB())
	blockExec := sm.NewBlockExecutor(
		stateStore,
		log.TestingLogger(),
		proxyApp.Consensus(),
		mmock.Mempool{},
		sm.EmptyEvidencePool{},
		blockStore,
	)

	block := sf.MakeBlock(state, 1, new(types.Commit))
	blockID := types.BlockID{Hash: block.Hash(), PartSetHeader: block.MakePartSet(testPartSize).Header()}

	vp, err := encoding.PubKeyToProto(state.Validators.Validators[0].PubKey)
	require.NoError(t, err)
	// Remove the only validator
	app.ValidatorUpdates = []abci.ValidatorUpdate{
		{PubKey: vp, Power: 0},
	}

	assert.NotPanics(t, func() { state, err = blockExec.ApplyBlock(state, blockID, block) })
	assert.NotNil(t, err)
	assert.NotEmpty(t, state.NextValidators.Validators)
}

func makeBlockID(hash []byte, partSetSize uint32, partSetHash []byte) types.BlockID {
	var (
		h   = make([]byte, tmhash.Size)
		psH = make([]byte, tmhash.Size)
	)
	copy(h, hash)
	copy(psH, partSetHash)
	return types.BlockID{
		Hash: h,
		PartSetHeader: types.PartSetHeader{
			Total: partSetSize,
			Hash:  psH,
		},
	}
}
