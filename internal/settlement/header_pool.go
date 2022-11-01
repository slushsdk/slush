package settlement

import (
	"github.com/tendermint/tendermint/types"
)

type HeaderPool struct {
	Headers []types.LightBlock
}
