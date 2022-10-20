package smartcontracts

import (
	"fmt"
	"os/exec"
)

func DeclareDeploy() ([]byte, error) {

	//Declare cairo contract
	cmd := exec.Command("protostar", "declare", "build/main.json", "--network", "alpha-goerli")
	cmd.Dir = "../../tendermint-cairo"

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Print(string(stdout))
		return stdout, err
	}

	//"get contract class hash out of return value"

	//Deploy cairo contract
	deploycmd := exec.Command("protostar", "deploy", "build/main.json", "--network", "alpha-goerli")
	deploycmd.Dir = "../../tendermint-cairo"

	deploystdout, err := deploycmd.CombinedOutput()

	if err != nil {

		return deploystdout, err
	}
	return []byte{}, nil
}
