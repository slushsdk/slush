package smartcontracts

import (
	"fmt"
	"math/big"
	"os/exec"
)

func Invoke(accountaddress big.Int) ([]byte, error) {

	//Declare cairo contract
	cmd := exec.Command("protostar", "migrate", "migrations/migrate_01.cairo", "--network", "alpha-goerli", "--private-key-path", "./pkey", "--account-address", fmt.Sprint(accountaddress))
	cmd.Dir = "../../tendermint-cairo"

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Print(string(stdout))
		return stdout, err
	}

	return stdout, err
}
