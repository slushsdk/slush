package smartcontracts_test

import (
	"math/big"
	"testing"

	"github.com/tendermint/tendermint/smartcontracts"
)

func TestDeclare(t *testing.T) {
	smartcontracts.DeclareDeploy()
	return
}

func TestInvoke(t *testing.T) {
	smartcontracts.Invoke(*big.NewInt(0))
	return
}
