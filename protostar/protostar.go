package protostar

import (
	"fmt"
	"os/exec"
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
func networkArgs(pConf *config.ProtostarConfig) (networkArgs []string) {
	networkArgs = []string{}
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--account-address", pConf.AccountAddress)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--chain-id", pConf.ChainId)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--gateway-url", pConf.GatewayUrl)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--network", pConf.Network)
	networkArgs = appendKeyWithValueIfNotEmpty(networkArgs, "--private-key-path", pConf.PrivateKeyPath)
	return
}

// executeCommand executes a command with the given args and returns the raw stdout and error
func executeCommand(pConf *config.ProtostarConfig, args []string) (cmdOutput []byte, err error) {
	if len(args) < 1 {
		err = fmt.Errorf("executeCommand: args must be non-empty")
		return
	}
	args = append(args, networkArgs(pConf)...)

	cmd := exec.Command(args[0], args[1:]...)

	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("response error: %w\nargs: %s\nstdout: %s", err, args, cmdOutput)
	}
	return
}

func regexFunctionFactory(regexString, objectName string) func(rawStdout []byte) (string, error) {
	return func(rawStdout []byte) (string, error) {
		regex := regexp.MustCompile(regexString)
		if !regex.Match(rawStdout) {
			return "", fmt.Errorf("could not find %s in stdout: %s", objectName, rawStdout)
		}
		return string(regex.FindSubmatch(rawStdout)[1]), nil
	}
}

func getClassHashHex(rawStdout []byte) (string, error) {
	return regexFunctionFactory(`(?m)^Class hash: (0x[A-Fa-f0-9]*$)`, "class hash hex")(rawStdout)
}

func getTransactionHashHex(rawStdout []byte) (string, error) {
	return regexFunctionFactory(`(?m)^Transaction hash: (0x[A-Fa-f0-9]*$)`, "transaction hash hex")(rawStdout)
}

func getTransactionHashFelt(rawStdout []byte) (string, error) {
	return regexFunctionFactory(`(?m)^Transaction hash: ([0-9]*$)`, "transaction hash felt")(rawStdout)
}

func getContractAddressHex(rawStdout []byte) (string, error) {
	return regexFunctionFactory(`(?m)^Contract address: (0x[A-Fa-f0-9]*$)`, "contract address hex")(rawStdout)
}

func Declare(pConf *config.ProtostarConfig, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"protostar", "declare", contractPath, "--max-fee", "auto"}

	stdout, err := executeCommand(pConf, commandArgs)
	if err != nil {
		err = fmt.Errorf("protostar declare command responded with an error:\n%s", err)
		return
	}

	if classHashHex, err = getClassHashHex(stdout); err != nil {
		return
	}
	if transactionHashHex, err = getTransactionHashHex(stdout); err != nil {
		return
	}
	return
}

func Deploy(pConf *config.ProtostarConfig, classHashHex string) (contractAddressHex, transactionHashFelt string, err error) {
	commandArgs := []string{"protostar", "deploy", classHashHex, "--max-fee", "auto"}

	stdout, err := executeCommand(pConf, commandArgs)
	if err != nil {
		err = fmt.Errorf("protostar deploy command responded with an error: %w", err)
		return
	}

	if contractAddressHex, err = getContractAddressHex(stdout); err != nil {
		return
	}
	if transactionHashFelt, err = getTransactionHashFelt(stdout); err != nil {
		return
	}
	return
}
