package smartcontracts

import (
	"fmt"
	"os/exec"

	"github.com/tendermint/tendermint/types"
)

func Invoke(types.VerifierDetails) ([]byte, error) {

	//Declare cairo contract
	cmd := exec.Command("protostar", "migrate", "migrations/migration_01.cairo", "--network", "alpha-goerli", "--private-key-path", "./pkey", "--account-address", "0x07e0e42703bE10f32F8c793395C3713141C15a3A80FF18e7515Df194DaC3eea7", "--output-dir", "migrations/output", "--no-confirm")
	cmd.Dir = "../../tendermint-cairo"

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Print(string(stdout))
		return stdout, err
	}

	fmt.Print(string(stdout))
	return stdout, err
}
