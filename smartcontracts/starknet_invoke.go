package smartcontracts

import (
	"fmt"
	"os/exec"

	"github.com/tendermint/tendermint/types"
)

func Invoke(vd types.VerifierDetails) ([]byte, error) {

	//Declare cairo contract

	cmd := exec.Command("protostar", "migrate", "migrations/migration_02.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key-path", vd.AccountPrivKeyPath, "--account-address", fmt.Sprint(vd.AccountAddress()), "--compiled-contracts-dir", "responses", "--no-confirm")
	cmd.Dir = "../../tendermint-cairo"

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Print(string(stdout))
		return stdout, err
	}

	fmt.Print(string(stdout))
	return stdout, err
}
