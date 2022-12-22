package protostar

import (
	"fmt"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/internal/settlement/utils"
)

func networkArgs(pConf *config.ProtostarConfig) (networkArgs []string) {
	networkArgs = []string{}
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--account-address", pConf.AccountAddress)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--chain-id", pConf.ChainId)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--gateway-url", pConf.GatewayUrl)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--network", pConf.Network)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--private-key-path", pConf.PrivateKeyPath)
	return
}

func getClassHashHex(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Class hash: (0x[A-Fa-f0-9]*$)`, "class hash hex")(rawStdout)
}

func getTransactionHashHex(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Transaction hash: (0x[A-Fa-f0-9]*$)`, "transaction hash hex")(rawStdout)
}

func getTransactionHashFelt(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Transaction hash: ([0-9]*$)`, "transaction hash felt")(rawStdout)
}

func getContractAddressHex(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Contract address: (0x[A-Fa-f0-9]*$)`, "contract address hex")(rawStdout)
}

func Declare(pConf *config.ProtostarConfig, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"protostar", "--no-color", "declare", contractPath, "--max-fee", "auto"}

	stdout, err := utils.ExecuteCommand(commandArgs, networkArgs(pConf))
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
	commandArgs := []string{"protostar", "--no-color", "deploy", classHashHex, "--max-fee", "auto"}

	stdout, err := utils.ExecuteCommand(commandArgs, networkArgs(pConf))
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

func Invoke(pConf *config.ProtostarConfig, contractAddress string, inputs []string) (transactionHashHex string, err error) {
	commandArgs := []string{
		"protostar", "--no-color", "invoke",
		"--contract-address", contractAddress,
		"--function", "externalVerifyAdjacent",
		"--max-fee", "auto",
		"--inputs"}
	commandArgs = append(commandArgs, inputs...)

	stdout, err := utils.ExecuteCommand(commandArgs, networkArgs(pConf))
	if err != nil {
		err = fmt.Errorf("protostar invoke command responded with an error: %w", err)
		return
	}

	if transactionHashHex, err = getTransactionHashHex(stdout); err != nil {
		return
	}
	return
}
