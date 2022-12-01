package settlement

import (
	"context"
	"sync"

	"github.com/tendermint/tendermint/internal/p2p"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"github.com/tendermint/tendermint/types"
)

// Reactor handles evpool evidence broadcasting amongst peers.
type Reactor struct {
	service.BaseService
	logger log.Logger

	headerPool    HeaderPool
	receiveBlocks <-chan types.LightBlock

	mtx sync.Mutex
}

// NewReactor returns a reference to a new evidence reactor, which implements the
// service.Service interface. It accepts a p2p Channel dedicated for handling
// envelopes with EvidenceList messages.
func NewReactor(
	logger log.Logger,
	chCreator p2p.ChannelCreator,
	peerEvents p2p.PeerEventSubscriber,
) *Reactor {
	r := &Reactor{
		logger:     logger,
		headerPool: HeaderPool{Headers: make([]types.LightBlock, 0)},
	}

	r.BaseService = *service.NewBaseService(logger, "Evidence", r)

	return r
}

// OnStart starts separate go routines for each p2p Channel and listens for
// envelopes on each. In addition, it also listens for peer updates and handles
// messages on that p2p channel accordingly. The caller must be sure to execute
// OnStop to ensure the outbound p2p Channels are closed. No error is returned.
func (r *Reactor) OnStart(ctx context.Context) error {

	return nil
}

// OnStop stops the reactor by signaling to all spawned goroutines to exit and
// blocking until they all exit.
func (r *Reactor) OnStop() {}
