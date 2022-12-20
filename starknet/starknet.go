package starknet

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/tendermint/tendermint/config"
)

// appendKeyWithValueIfNotEmpty appends the given key and value to the args if the value is not empty
func appendKeyWithValueIfNotEmpty(args []string, arg, value string) []string {
	if value != "" {
		return append(args, arg, value)
	}
	return args
}

// networkArgs returns the network args for the starknet cli
func networkArgs(sConf *config.StarknetConfig) (networkArgs []string) {
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--account", sConf.Account)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--account_dir", sConf.AccountDir)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--feeder_gateway_url", sConf.FeederGatewayURL)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--gateway_url", sConf.GatewayURL)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--network", sConf.Network)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--wallet", sConf.Wallet)
	return
}

// execute executes a command with the given args and returns the raw stdout and error
func executeCommand(sConf *config.StarknetConfig, args []string) (cmdOutput []byte, err error) {
	if len(args) < 1 {
		err = fmt.Errorf("executeCommand: args must be non-empty")
		return
	}
	args = append(args, networkArgs(sConf)...)

	cmd := exec.Command(args[0], args[1:]...)

	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("response error: %w\nargs: %s\nstdout: %s", err, args, cmdOutput)
	}
	return
}

func Declare(sConf *config.StarknetConfig, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "declare", "--contract", contractPath}

	stdout, err := executeCommand(sConf, commandArgs)
	if err != nil {
		err = fmt.Errorf("starknet declare command responded with an error:\n%s", err)
		return
	}

	contractClassHashRegex := regexp.MustCompile(`(?m)^Contract class hash: (0x[A-Fa-f0-9]*$)`)
	if !contractClassHashRegex.Match(stdout) {
		err = fmt.Errorf("could not find contract class hash in stdout: %s", stdout)
		return
	}

	transactionHashRegex := regexp.MustCompile(`(?m)^Transaction hash: (0x[A-Fa-f0-9]*$)`)
	if !transactionHashRegex.Match(stdout) {
		err = fmt.Errorf("could not find transaction hash in stdout: %s", stdout)
		return
	}

	classHashHex = string(contractClassHashRegex.FindSubmatch(stdout)[1])
	transactionHashHex = string(transactionHashRegex.FindSubmatch(stdout)[1])
	return
}

func Deploy(sConf *config.StarknetConfig, classHashHex string) (contractAddressHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "deploy", "--class_hash", classHashHex}

	stdout, err := executeCommand(sConf, commandArgs)
	if err != nil {
		err = fmt.Errorf("starknet deploy command responded with an error: %w", err)
		return
	}

	contractAddressRegex := regexp.MustCompile(`(?m)^Contract address: (0x[A-Fa-f0-9]*$)`)
	if !contractAddressRegex.Match(stdout) {
		err = fmt.Errorf("could not find contract address in stdout: %s", stdout)
		return
	}

	transactionHashRegex := regexp.MustCompile(`(?m)^Transaction hash: (0x[A-Fa-f0-9]*$)`)
	if !transactionHashRegex.Match(stdout) {
		err = fmt.Errorf("could not find transaction hash in stdout: %s", stdout)
		return
	}

	contractAddressHex = string(contractAddressRegex.FindSubmatch(stdout)[1])
	transactionHashHex = string(transactionHashRegex.FindSubmatch(stdout)[1])
	return
}

func Invoke(conf *config.Config, inputs []string) (transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "invoke", "--address", conf.VerifierAddress, "--abi", filepath.Join(conf.CairoDir, "build/main_abi.json"), "--function", "externalVerifyAdjacent", "--inputs"}
	commandArgs = append(commandArgs, inputs...)

	stdout, err := executeCommand(conf.Starknet, commandArgs)
	// fmt.Println(string(stdout))
	if err != nil {
		err = fmt.Errorf("starknet invoke command responded with an error: %w", err)
		return
	}

	transactionHashRegex := regexp.MustCompile(`(?m)^Transaction hash: (0x[A-Fa-f0-9]*$)`)
	if !transactionHashRegex.Match(stdout) {
		err = fmt.Errorf("could not find transaction hash in stdout: %s", stdout)
		return
	}

	transactionHashHex = string(transactionHashRegex.FindSubmatch(stdout)[1])
	return
}
