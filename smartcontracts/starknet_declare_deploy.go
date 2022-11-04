package smartcontracts

import (
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"regexp"

	"github.com/tendermint/tendermint/types"
)

// struct ContractAddressStruct{

// }

// struct

func DeclareDeploy(vd types.VerifierDetails, verifierDetailsFile string) (*big.Int, *big.Int, error) {

	//"get contract class hash out of return value"

	//Deploy cairo contract
	var deploycmd *exec.Cmd

	// devnet is different
	if vd.NetworkDetails.Network == "devnet" {
		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--gateway-url", "http://127.0.0.1:5050/", "--chain-id", "1536727068981429685321", "--private-key", "./"+vd.AccountPrivKeyPath, "--account-address", vd.AccountAddress.Text(16), "--no-confirm")
		deploycmd.Dir = vd.PathToFiles
	} else {
		deploycmd = exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--private-key", vd.AccountPrivKeyPath, "--account-address", vd.AccountAddress.String(), "--network", vd.NetworkDetails.Network, "--no-confirm")
		deploycmd.Dir = vd.PathToFiles
	}

	deploystdout, err := deploycmd.CombinedOutput()
	fmt.Println(string(deploystdout))

	contractA := regexp.MustCompile(`contract_address *.*?\n`)
	classH := regexp.MustCompile(`class_hash *.*?\n`)

	zerox := regexp.MustCompile(`0x.{64}`)
	verifierAddress, b := big.NewInt(0).SetString(string(zerox.Find(contractA.Find(deploystdout)))[2:], 16)

	if b != true {
		return big.NewInt(0), big.NewInt(0), errors.New("Was not able to parse verifier address in starknet declare/deploy output")
	}

	classHash, b := big.NewInt(0).SetString(string(zerox.Find(classH.Find(deploystdout))[2:]), 16)
	if b != true {
		return big.NewInt(0), big.NewInt(0), errors.New("Was not able to parse class hash in starknet declare/deploy output")
	}

	vd.VerifierAddress = verifierAddress
	vd.SaveAs(verifierDetailsFile)

	return verifierAddress, classHash, err
}
