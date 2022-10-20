package smartcontracts

import (
	"fmt"
	"os/exec"

	"github.com/tendermint/tendermint/cmd/tendermint/commands"
	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
)

func DeclareDeploy() {

	conf, err := commands.ParseConfig(config.DefaultConfig())
	if err != nil {
		panic(err)
	}

	logger, err := log.NewDefaultLogger(conf.LogFormat, conf.LogLevel)
	if err != nil {
		panic(err)
	}

	//Declare cairo contract
	cmd := exec.Command("starknet", "declare", "--contract", "../../tendermint-cairo/build/main.json", "--network=alpha-goerli", "--wallet", "0x07e0e42703bE10f32F8c793395C3713141C15a3A80FF18e7515Df194DaC3eea7")

	stdout, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Print(string(stdout))
		logger.Error("Failed to declare Cairo contracts", err)
		return
	}

	logger.Info(string(stdout))
	//"get contract class hash out of return value"

	//Deploy cairo contract
	deploycmd := exec.Command("starknet", "deploy", "--address", "0x0133e47cb63dc572bb8296cdc401cc08639cb712201f80eed4b6e95b0b20ba0b", "--abi", "../../tendermint-cairo/build/main_abi.json", "--function", "externalVerifyAdjacent", "--inputs")

	deploystdout, err := deploycmd.CombinedOutput()

	if err != nil {
		logger.Error("Failed to deploy Cairo contracts", err)
		return
	}

	logger.Info(string(deploystdout))
}
