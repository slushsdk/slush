package mempool

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/types"
)

func TestMempoolIDsBasic(t *testing.T) {
	ids := NewMempoolIDs()
	pb := ed25519.GenPrivKey().PubKey()
	peerID, err := types.NewNodeID(fmt.Sprint(pb.Address()))
	require.NoError(t, err)

	ids.ReserveForPeer(peerID)
	require.EqualValues(t, 1, ids.GetForPeer(peerID))
	ids.Reclaim(peerID)

	ids.ReserveForPeer(peerID)
	require.EqualValues(t, 2, ids.GetForPeer(peerID))
}

func TestMempoolIDsPeerDupReserve(t *testing.T) {
	ids := NewMempoolIDs()
	pb := ed25519.GenPrivKey().PubKey()
	peerID, err := types.NewNodeID(fmt.Sprint(pb.Address()))
	require.NoError(t, err)
	require.EqualValues(t, 0, ids.GetForPeer(peerID))

	ids.ReserveForPeer(peerID)
	require.EqualValues(t, 1, ids.GetForPeer(peerID))

	ids.ReserveForPeer(peerID)
	require.EqualValues(t, 2, ids.GetForPeer(peerID))
}

func TestMempoolIDs2Peers(t *testing.T) {
	ids := NewMempoolIDs()

	pb := ed25519.GenPrivKey().PubKey()
	peer1ID, _ := types.NewNodeID(fmt.Sprint(pb.Address()))
	require.EqualValues(t, 0, ids.GetForPeer(peer1ID))

	ids.ReserveForPeer(peer1ID)
	require.EqualValues(t, 1, ids.GetForPeer(peer1ID))

	ids.Reclaim(peer1ID)
	require.EqualValues(t, 0, ids.GetForPeer(peer1ID))

	pb2 := ed25519.GenPrivKey().PubKey()
	peer2ID, _ := types.NewNodeID(fmt.Sprint(pb2.Address()))

	ids.ReserveForPeer(peer2ID)
	require.EqualValues(t, 2, ids.GetForPeer(peer2ID))

	ids.ReserveForPeer(peer1ID)
	require.EqualValues(t, 3, ids.GetForPeer(peer1ID))
}

func TestMempoolIDsNextExistID(t *testing.T) {
	ids := NewMempoolIDs()

	pb := ed25519.GenPrivKey().PubKey()
	peer1ID, _ := types.NewNodeID(fmt.Sprint(pb.Address()))
	ids.ReserveForPeer(peer1ID)
	require.EqualValues(t, 1, ids.GetForPeer(peer1ID))

	pb2 := ed25519.GenPrivKey().PubKey()
	peer2ID, _ := types.NewNodeID(fmt.Sprint(pb2.Address()))
	ids.ReserveForPeer(peer2ID)
	require.EqualValues(t, 2, ids.GetForPeer(peer2ID))

	pb3 := ed25519.GenPrivKey().PubKey()
	peer3ID, _ := types.NewNodeID(fmt.Sprint(pb3.Address()))
	ids.ReserveForPeer(peer3ID)
	require.EqualValues(t, 3, ids.GetForPeer(peer3ID))

	ids.Reclaim(peer1ID)
	require.EqualValues(t, 0, ids.GetForPeer(peer1ID))

	ids.Reclaim(peer3ID)
	require.EqualValues(t, 0, ids.GetForPeer(peer3ID))

	ids.ReserveForPeer(peer1ID)
	require.EqualValues(t, 4, ids.GetForPeer(peer1ID))

	ids.ReserveForPeer(peer3ID)
	require.EqualValues(t, 5, ids.GetForPeer(peer3ID))
}
