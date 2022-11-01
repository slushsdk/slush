package settlement

import (
	"github.com/tendermint/tendermint/types"
)

type headerPool struct {
	headers []types.LightBlock
}
