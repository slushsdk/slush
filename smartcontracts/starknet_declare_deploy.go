package smartcontracts

import (
	"fmt"
	"os/exec"
)

// struct ContractAddressStruct{

// }

// struct

func DeclareDeploy() ([]byte, error) {

	//Declare cairo contract
	// cmd := exec.Command("protostar", "declare", "build/main.json", "--network", "alpha-goerli")
	// cmd.Dir = "../../tendermint-cairo"

	// stdout, err := cmd.CombinedOutput()

	// if err != nil {
	// 	fmt.Print(string(stdout))
	// 	return stdout, err
	// }

	//"get contract class hash out of return value"

	//Deploy cairo contract
	deploycmd := exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--network", "alpha-goerli", "--output-dir", "responses/", "--no-confirm")

	// deploycmd1 := exec.Command("protostar", "deploy", "build/main.json", "--network", "alpha-goerli", "--output-dir", "response.json")
	deploycmd.Dir = "../../tendermint-cairo"

	deploystdout, err := deploycmd.CombinedOutput()

	if err != nil {
		fmt.Println(string(deploystdout))

		return deploystdout, err
	}
	fmt.Println(string(deploystdout))
	// json.Unmarshal(deploystdout, ContractAddressStruct)
	return []byte{}, nil
}
