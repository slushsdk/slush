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
func networkArgs(conf *config.Config) (networkArgs []string) {
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--account", conf.Starknet.Account)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--account_dir", conf.GetAccountDir())
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--feeder_gateway_url", conf.Starknet.FeederGatewayURL)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--gateway_url", conf.Starknet.GatewayURL)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--network", conf.Starknet.Network)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--wallet", conf.Starknet.Wallet)
	return
}

// executeWithPath executes a command with the given args and path
// and returns the raw stdout and error
func executeWithPath(conf *config.Config) func(executePath string, args []string) (cmdOutput []byte, err error) {
	return func(executePath string, args []string) (cmdOutput []byte, err error) {
		if len(args) < 1 {
			err = fmt.Errorf("executeWithPath: args must be non-empty")
			return
		}
		args = append(args, networkArgs(conf)...)

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = executePath

		cmdOutput, err = cmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("response error: %w\nexecutionPath: %s\nargs: %s\nstdout: %s", err, executePath, args, cmdOutput)
		}
		return
	}
}

// execute executes a command with the given args and returns the raw stdout and error
func executeCommand(conf *config.Config) func(args []string) (cmdOutput []byte, err error) {
	return func(args []string) (cmdOutput []byte, err error) {
		return executeWithPath(conf)(".", args)
	}
}

func Declare(conf *config.Config, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "declare", "--contract", contractPath}

	stdout, err := executeCommand(conf)(commandArgs)
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

func Deploy(conf *config.Config, classHashHex string) (contractAddressHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "deploy", "--class_hash", classHashHex}

	stdout, err := executeCommand(conf)(commandArgs)
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

	stdout, err := executeCommand(conf)(commandArgs)
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
