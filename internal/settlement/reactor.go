package settlement

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/internal/consensus"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/starknet"
)

// Reactor handles light blocks sent for settlement. Slush addition, modelled of evidence reactor.
type Reactor struct {
	service.BaseService
	logger       log.Logger
	cfg          *config.Config
	SettlementCh <-chan consensus.InvokeData
	stopChan     chan bool
}

// NewReactor returns a reference to a new evidence reactor, which implements the
// service.Service interface. It accepts a p2p Channel dedicated for handling
// envelopes with EvidenceList messages.
func NewReactor(
	logger log.Logger,
	cfg *config.Config,
	SettlementCh <-chan consensus.InvokeData,
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
func (r *Reactor) OnStart(ctx context.Context) error {
	go r.ListenInvokeBlocks(ctx, r.SettlementCh)

	return nil
}

// OnStop stops the reactor by signaling to all spawned goroutines to exit and
// blocking until they all exit.
func (r *Reactor) OnStop() {
	r.stopChan <- true
}

func (r *Reactor) ListenInvokeBlocks(ctx context.Context, SettlementCh <-chan consensus.InvokeData) {
	r.logger.Info("started settlement reactor")
	for {
		select {
		case newBlock := <-SettlementCh:
			r.FormatAndSendCommit(newBlock)
		case <-ctx.Done():
			r.logger.Info("Stopping settlement reactor via context")

			return
		case <-r.stopChan:
			r.logger.Info("Stopping settlement reactor via stopChan")

			return
		}
	}
}

func format(id consensus.InvokeData) (jsonString string, err error) {
	currentTime := big.NewInt((time.Now().UnixNano()))
	maxClockDrift := big.NewInt(10)
	trustingPeriod, _ := big.NewInt(0).SetString("99999999999999999999", 10)

	cd := consensus.FormatCallData(id.TrustedLightB, id.UntrustedLightB, &id.ValidatorSet, currentTime, maxClockDrift, trustingPeriod)
	jsonBytes, err := json.Marshal(cd)
	if err != nil {
		panic(err)
	}
	jsonString = string(jsonBytes)
	return
}

func (r *Reactor) FormatAndSendCommit(id consensus.InvokeData) (err error) {
	logger := r.logger
	logger.Info("settling commit")

	jsonString, err := format(id)
	if err != nil {
		err = fmt.Errorf("failed to format call data: %w", err)
		return
	}
	transactionHashHex, err := starknet.InvokeSimplified(r.cfg, jsonString)
	if err != nil {
		err = fmt.Errorf("failed to invoke starknet contract: %w", err)
		return
	}
	logger.Info("transaction hash", "hash", transactionHashHex)
	return
}
