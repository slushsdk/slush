package settlement

import (
	"fmt"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/internal/settlement/parser"
	"github.com/tendermint/tendermint/internal/settlement/protostar"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
)

// Reactor handles light blocks sent for settlement. Slush addition, modelled of evidence reactor.
type Reactor struct {
	service.BaseService
	logger       log.Logger
	cfg          *config.Config
	SettlementCh <-chan parser.SettlementData
	stopChan     chan bool
}

// NewReactor returns a reference to a new evidence reactor, which implements the
// service.Service interface. It accepts a p2p Channel dedicated for handling
// envelopes with EvidenceList messages.
func NewReactor(
	logger log.Logger,
	cfg *config.Config,
	SettlementCh <-chan parser.SettlementData,
) *Reactor {
	r := &Reactor{
		logger:       logger,
		cfg:          cfg,
		SettlementCh: SettlementCh,
	}

	r.BaseService = *service.NewBaseService(logger, "Settlement", r)

	return r
}

// OnStart starts separate go routines for each p2p Channel and listens for
// envelopes on each. In addition, it also listens for peer updates and handles
// messages on that p2p channel accordingly. The caller must be sure to execute
// OnStop to ensure the outbound p2p Channels are closed. No error is returned.
func (r *Reactor) OnStart() error {
	go r.ListenInvokeBlocks(r.SettlementCh)

	return nil
}

// OnStop stops the reactor by signaling to all spawned goroutines to exit and
// blocking until they all exit.
func (r *Reactor) OnStop() {
	r.stopChan <- true
}

func (r *Reactor) ListenInvokeBlocks(SettlementCh <-chan parser.SettlementData) {
	r.logger.Info("started settlement reactor")
	for {
		select {
		case newBlock := <-SettlementCh:
			err := r.SendCommit(newBlock)
			if err != nil {
				r.logger.Error("failed to send commit", "err", err)
			}
		case <-r.stopChan:
			r.logger.Info("Stopping settlement reactor via stopChan")

			return
		}
	}
}

func (r *Reactor) SendCommit(inputs parser.SettlementData) (err error) {
	logger := r.logger
	logger.Info("settling commit")

	err = protostar.Invoke(logger, r.cfg.Protostar, r.cfg.VerifierAddress, "externalVerifyAdjacent", inputs)
	if err != nil {
		err = fmt.Errorf("failed to invoke starknet contract: %w", err)
		return
	}
	logger.Info("block recorded for settlement")
	return
}
