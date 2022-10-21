package smartcontracts_test

import (
	"testing"

	"github.com/tendermint/tendermint/smartcontracts"
	"github.com/tendermint/tendermint/types"
)

func TestDeclare(t *testing.T) {
	smartcontracts.DeclareDeploy()
	return
}

func TestInvoke(t *testing.T) {
	vd := types.VerifierDetails{}
	smartcontracts.Invoke(vd)
	return
}
