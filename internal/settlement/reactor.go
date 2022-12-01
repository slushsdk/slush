package settlement

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/tendermint/tendermint/internal/consensus"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/smartcontracts"
	"github.com/tendermint/tendermint/types"
)

// Reactor handles light blocks sent for settlement. Slush addition, modelled of evidence reactor.
type Reactor struct {
	service.BaseService
	logger log.Logger

	verifierDetails types.VerifierDetails
	SettlementCh    <-chan consensus.InvokeData

	mtx sync.Mutex
}

// NewReactor returns a reference to a new evidence reactor, which implements the
// service.Service interface. It accepts a p2p Channel dedicated for handling
// envelopes with EvidenceList messages.
func NewReactor(
	logger log.Logger,
	vd types.VerifierDetails,
	SettlementCh <-chan consensus.InvokeData,
) *Reactor {
	r := &Reactor{
		logger:          logger,
		verifierDetails: vd,
		SettlementCh:    SettlementCh,
	}

	r.BaseService = *service.NewBaseService(logger, "Settlement", r)

	return r
}

// OnStart starts separate go routines for each p2p Channel and listens for
// envelopes on each. In addition, it also listens for peer updates and handles
// messages on that p2p channel accordingly. The caller must be sure to execute
// OnStop to ensure the outbound p2p Channels are closed. No error is returned.
func (r *Reactor) OnStart(ctx context.Context) error {
	go r.ListenInvokeBlocks(ctx, r.SettlementCh)

	return nil
}

// OnStop stops the reactor by signaling to all spawned goroutines to exit and
// blocking until they all exit.
func (r *Reactor) OnStop() {}

func (r *Reactor) ListenInvokeBlocks(ctx context.Context, SettlementCh <-chan consensus.InvokeData) {
	r.logger.Info("started settlement reactor")
	for {
		select {
		case newBlock := <-SettlementCh:
			r.FormatAndSendCommit(newBlock)
		case <-ctx.Done():
			r.logger.Info("Stopping settlement reactor")

			return
		}
	}
}

func (r *Reactor) FormatAndSendCommit(id consensus.InvokeData) error {
	logger := r.logger
	logger.Info("settling commit")
	currentTime := time.Now()
	timeBig := big.NewInt((currentTime.UnixNano()))

	stdout, err := smartcontracts.Invoke(r.verifierDetails, id, timeBig)
	logger.Info(fmt.Sprintf("CAIRO: %s", stdout))
	if err != nil {
		fmt.Println(err)

	}
	return err
}
