package smartcontracts

import (
	"encoding/json"
	"io/fs"
	"math/big"
	"os"
	"os/exec"

	"github.com/tendermint/tendermint/internal/consensus"
	"github.com/tendermint/tendermint/types"
)

func Invoke(vd types.VerifierDetails, id consensus.InvokeData, currentTime *big.Int) ([]byte, error) {

	trustingPeriod, _ := big.NewInt(0).SetString("99999999999999999999", 10)

	cd := consensus.FormatCallData(id.TrustedLightB, id.UntrustedLightB, &id.ValidatorSet, currentTime, big.NewInt(10), trustingPeriod)
	ext := consensus.External{VerifierAddress: vd.VerifierAddress, CallData: cd}
	jsonString, _ := json.Marshal(ext)

	err := os.WriteFile("./cairo/migrations/invoke_input.json", jsonString, fs.FileMode(0644))

	if err != nil {
		return []byte{}, err
	}

	// devnet is different
	var cmd *exec.Cmd
	if vd.NetworkDetails.Network == "devnet" {
		// eg protostar migrate migrations/migration_02.cairo --gateway-url "http://127.0.0.1:5050/" --chain-id 1536727068981429685321 --private-key-path ./seed42pkey --account-address "347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a" --no-confirm
		cmd = exec.Command("protostar", "migrate", "migrations/migration_02.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key-path", vd.AccountPrivKeyPath, "--account-address", vd.AccountAddress.Text(16), "--no-confirm")
		cmd.Dir = "./cairo"
	} else {
		cmd = exec.Command("protostar", "migrate", "migrations/migration_02.cairo", "--network", vd.NetworkDetails.Network, "--private-key-path", vd.AccountPrivKeyPath, "--account-address", vd.AccountAddress.Text(16), "--no-confirm")
		cmd.Dir = "./cairo"
	}

	stdout, err := cmd.CombinedOutput()

	return stdout, err
}
