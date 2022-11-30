package smartcontracts

import (
	"fmt"
	"os/exec"

	"github.com/tendermint/tendermint/types"
)

func Invoke(vd types.VerifierDetails) ([]byte, error) {

	//Declare cairo contract

	cmd := exec.Command("protostar", "migrate", "migrations/migration_02.cairo", "--network", "alpha-goerli", "--private-key-path", vd.AccountPrivKeyPath, "--account-address", fmt.Sprint(vd.AccountAddress()), "--output-dir", "responses", "--no-confirm")
	cmd.Dir = "../../tendermint-cairo"

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Print(string(stdout))
		return stdout, err
	}

	fmt.Print(string(stdout))
	return stdout, err
}
