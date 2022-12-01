package smartcontracts

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
)

// struct ContractAddressStruct{

// }

// struct

func DeclareDeploy(pathToFiles string, network string, devnetbool bool) (*big.Int, *big.Int, error) {

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
				return big.NewInt(0), big.NewInt(0), err
			}

			addressBytes, err := os.ReadFile(pathToFiles + "/address")
			if err != nil {
				return big.NewInt(0), big.NewInt(0), err
			}
			deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key", string(pkeyBytes), "--account-address", string(addressBytes), "--no-confirm")
			deploycmd.Dir = pathToFiles
		}

	} else {

		pkeyBytes, err := os.ReadFile(pathToFiles + "/pkey")
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}

		addressBytes, err := os.ReadFile(pathToFiles + "/address")
		if err != nil {
			return big.NewInt(0), big.NewInt(0), err
		}

		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", string(pkeyBytes), "--account-address", string(addressBytes), "--network", network, "--no-confirm")
		deploycmd.Dir = pathToFiles
	}

	deploystdout, err := deploycmd.CombinedOutput()

	contractA := regexp.MustCompile(`contract_address *.*?\n`)
	classH := regexp.MustCompile(`class_hash *.*?\n`)

	zerox := regexp.MustCompile(`0x.{64}`)
	contractAddress, b := big.NewInt(0).SetString(string(zerox.Find(contractA.Find(deploystdout)))[2:], 16)

	if b != true {
		fmt.Println(deploystdout)
		return big.NewInt(0), big.NewInt(0), errors.New("Was not able to parse address starknet declare/deploy output")
	}

	classHash, b := big.NewInt(0).SetString(string(zerox.Find(classH.Find(deploystdout))[2:]), 16)
	if b != true {
		fmt.Println(deploystdout)
		return big.NewInt(0), big.NewInt(0), errors.New("Was not able to parse class hash in starknet declare/deploy output")
	}

	fmt.Println(string(deploystdout))

	return contractAddress, classHash, err
}
