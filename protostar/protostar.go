package protostar

import (
	"fmt"
	"os/exec"

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
