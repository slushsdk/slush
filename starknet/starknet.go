package starknet

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/tendermint/tendermint/config"
)

func appendIfNotEmpty(args []string, arg, value string) []string {
	if value != "" {
		return append(args, arg, value)
	}
	return args
}

func networkArgs(sc *config.StarknetConfig) (networkArgs []string) {
	networkArgs = appendIfNotEmpty(networkArgs, "--network", sc.Network)
	networkArgs = appendIfNotEmpty(networkArgs, "--gateway_url", sc.GatewayURL)
	networkArgs = appendIfNotEmpty(networkArgs, "--feeder_gateway_url", sc.FeederGatewayURL)
	networkArgs = appendIfNotEmpty(networkArgs, "--wallet", sc.Wallet)
	networkArgs = appendIfNotEmpty(networkArgs, "--account", sc.Account)
	return
}

// executeCommandWithPath executes a command with the given args and path
// and returns the raw stdout and error
func executeCommandWithPath(sc *config.StarknetConfig) func(executePath string, args []string) (cmdOutput []byte, err error) {
	return func(executePath string, args []string) (cmdOutput []byte, err error) {
		if len(args) < 1 {
			err = fmt.Errorf("executeCommand: args must be non-empty")
			return
		}
		args = append(args, networkArgs(sc)...)

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = executePath

		cmdOutput, err = cmd.CombinedOutput()
		if err != nil {
			err = fmt.Errorf("response error: %w\nexecutionPath: %s\nargs: %s\nstdout: %s", err, executePath, args, cmdOutput)
		}
		return
	}
}

// executeCommand executes a command with the given args and returns the raw stdout and error
func executeCommand(sc *config.StarknetConfig) func(args []string) (cmdOutput []byte, err error) {
	return func(args []string) (cmdOutput []byte, err error) {
		return executeCommandWithPath(sc)(".", args)
	}
}

func Declare(sc *config.StarknetConfig, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "declare", "--contract", contractPath}

	stdout, err := executeCommand(sc)(commandArgs)
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

func Deploy(sc *config.StarknetConfig, classHashHex string) (contractAddressHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "deploy", "--class_hash", classHashHex}

	stdout, err := executeCommand(sc)(commandArgs)
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

func Invoke(sc *config.StarknetConfig, contractAddressHex, contractAbiPath, functionName, inputs string) (transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "invoke", "--address", contractAddressHex, "--abi", contractAbiPath, "--function", functionName, "--inputs"}

	stdout, err := executeCommand(sc)(commandArgs)
	if err != nil {
		err = fmt.Errorf("starknet invoke command responded with an error: %w", err)
		return
	}

	transactionHashRegex := regexp.MustCompile(`(?m)^Transaction hash: (0x[A-Fa-f0-9]{63}$)`)
	if !transactionHashRegex.Match(stdout) {
		err = fmt.Errorf("could not find transaction hash in stdout: %s", stdout)
		return
	}

	transactionHashHex = string(transactionHashRegex.FindSubmatch(stdout)[1])
	return
}

func InvokeSimplified(conf *config.Config, inputs string) (transactionHashHex string, err error) {
	return Invoke(conf.Starknet, conf.VerifierAddress, filepath.Join(conf.CairoDir, "build/main_abi.json"), "externalVerifyAdjacent", inputs)
}
