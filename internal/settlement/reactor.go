package settlement

import (
	"context"
	"fmt"
	"sync"

	"github.com/tendermint/tendermint/internal/p2p"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/types"
)

var _ service.Service = (*Reactor)(nil)

const (
	maxMsgSize = 1048576 // 1MB TODO make it configurable

	// broadcast all uncommitted evidence this often. This sets when the reactor
	// goes back to the start of the list and begins sending the evidence again.
	// Most evidence should be committed in the very next block that is why we wait
	// just over the block production rate before sending evidence again.
	broadcastEvidenceIntervalS = 10
)

// Reactor handles evpool evidence broadcasting amongst peers.
type Reactor struct {
	service.BaseService
	logger log.Logger

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
		logger: logger,
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

// handleEvidenceMessage handles envelopes sent from peers on the EvidenceChannel.
// It returns an error only if the Envelope.Message is unknown for this channel
// or if the given evidence is invalid. This should never be called outside of
// handleMessage.
func (r *Reactor) handleEvidenceMessage(ctx context.Context, envelope *p2p.Envelope) error {
	logger := r.logger.With("peer", envelope.From)

	switch msg := envelope.Message.(type) {
	case *tmproto.Evidence:
		// Process the evidence received from a peer
		// Evidence is sent and received one by one
		_, err := types.EvidenceFromProto(msg)
		if err != nil {
			logger.Error("failed to convert evidence", "err", err)
			return err
		}

	default:
		return fmt.Errorf("received unknown message: %T", msg)
	}

	return nil
}
