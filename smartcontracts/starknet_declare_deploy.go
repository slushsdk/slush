package smartcontracts

import (
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"regexp"
)

// struct ContractAddressStruct{

// }

// struct

func DeclareDeploy(accountAddress, accountPrivateKeyPath, network string) (verifierAddress *big.Int, classHash *big.Int, err error) {

	//"get contract class hash out of return value"

	//Deploy cairo contract
	var deploycmd *exec.Cmd

	// devnet is different
	if network == "devnet" {
		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key", "./"+accountPrivateKeyPath, "--account-address", "0x"+accountAddress, "--no-confirm")
		deploycmd.Dir = "./cairo"
	} else if network == "testnet2" {
		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--gateway-url", "https://alpha4-2.starknet.io", "--chain-id", "1536727068981429685321", "--private-key", "./"+accountPrivateKeyPath, "--account-address", "0x"+accountAddress, "--no-confirm")
		deploycmd.Dir = "./cairo"

	} else {
		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--private-key", accountPrivateKeyPath, "--account-address", accountAddress, "--network", network, "--no-confirm")
		deploycmd.Dir = "./cairo"
	}

	deploystdout, err := deploycmd.CombinedOutput()
	fmt.Println(string(deploystdout))

	contractA := regexp.MustCompile(`contract_address *.*?\n`)
	classH := regexp.MustCompile(`class_hash *.*?\n`)

	zerox := regexp.MustCompile(`0x.{64}`)

	verifierAddress, ok := big.NewInt(0).SetString(string(zerox.Find(contractA.Find(deploystdout)))[2:], 16)
	if !ok {
		err = errors.New("was not able to parse verifier address in starknet declare/deploy output")
		return
	}

	classHash, ok = big.NewInt(0).SetString(string(zerox.Find(classH.Find(deploystdout))[2:]), 16)
	if !ok {
		err = errors.New("was not able to parse class hash in starknet declare/deploy output")
		return
	}

	return
}
