package smartcontracts

import (
	"fmt"
	"os"
	"os/exec"
)

// struct ContractAddressStruct{

// }

// struct

func DeclareDeploy(pathToFiles string, network string, devnetbool bool) ([]byte, error) {

	//"get contract class hash out of return value"

	//Deploy cairo contract
	// Is the pkey/address formatting correct?
	var deploycmd *exec.Cmd
	// devnet is different
	if network == "devnet" {
		//  do we have keys for devnet? if
		if devnetbool {
			os.WriteFile(pathToFiles+"/seed42pkey", []byte{}, 0666)
			os.Truncate(pathToFiles+"/seed42pkey", 0)
			os.WriteFile(pathToFiles+"/seed42pkey", []byte("bdd640fb06671ad11c80317fa3b1799d"), 0666)

			deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key", pathToFiles+"/seed42pkey", "--account-address", "347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a", "--no-confirm")
			deploycmd.Dir = pathToFiles
		} else {
			pkeyBytes, err := os.ReadFile(pathToFiles + "/pkey")
			if err != nil {
				return []byte{}, err
			}

			addressBytes, err := os.ReadFile(pathToFiles + "/address")
			if err != nil {
				return []byte{}, err
			}
			deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key", string(pkeyBytes), "--account-address", string(addressBytes), "--no-confirm")
			deploycmd.Dir = pathToFiles
		}

	} else {

		pkeyBytes, err := os.ReadFile(pathToFiles + "/pkey")
		if err != nil {
			return []byte{}, err
		}

		addressBytes, err := os.ReadFile(pathToFiles + "/address")
		if err != nil {
			return []byte{}, err
		}

		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", string(pkeyBytes), "--account-address", string(addressBytes), "--network", network, "--no-confirm")
		deploycmd.Dir = pathToFiles
	}

	deploystdout, err := deploycmd.CombinedOutput()

	fmt.Println(string(deploystdout))
	return deploystdout, err
}
