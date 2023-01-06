package starknet

import (
	"fmt"
	"path/filepath"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/internal/settlement/utils"
)

func NetworkArgsForSends(conf *config.Config) (networkArgs []string) {
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--account", conf.Starknet.Account)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--account_dir", conf.Starknet.AccountDir)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--feeder_gateway_url", conf.Starknet.FeederGatewayURL)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--gateway_url", conf.Starknet.GatewayURL)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--network", conf.Starknet.Network)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--wallet", conf.Starknet.Wallet)
	return
}

func NetworkArgsForGetTransaction(conf *config.StarknetConfig) (networkArgs []string) {
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--gateway_url", conf.GatewayURL)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--feeder_gateway_url", conf.FeederGatewayURL)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--network", conf.Network)
	return
}

func getContractClassHashHex(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Contract class hash: (0x[A-Fa-f0-9]*$)`, "class hash hex")(rawStdout)
}

func getTransactionHashHex(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Transaction hash: (0x[A-Fa-f0-9]*$)`, "transaction hash hex")(rawStdout)
}

func getContractAddressHex(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^Contract address: (0x[A-Fa-f0-9]*$)`, "contract address hex")(rawStdout)
}

func Declare(conf *config.Config, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "declare", "--contract", contractPath}

	stdout, err := utils.ExecuteCommand(commandArgs, NetworkArgsForSends(conf))
	if err != nil {
		err = fmt.Errorf("starknet declare command responded with an error:\n%s", err)
		return
	}

	if classHashHex, err = getContractClassHashHex(stdout); err != nil {
		return
	}
	if transactionHashHex, err = getTransactionHashHex(stdout); err != nil {
		return
	}
	return
}

func Deploy(conf *config.Config, classHashHex string) (contractAddressHex, transactionHashHex string, err error) {
	commandArgs := []string{"starknet", "deploy", "--class_hash", classHashHex}

	stdout, err := utils.ExecuteCommand(commandArgs, NetworkArgsForSends(conf))
	if err != nil {
		err = fmt.Errorf("starknet deploy command responded with an error: %w", err)
		return
	}

	if contractAddressHex, err = getContractAddressHex(stdout); err != nil {
		return
	}
	if transactionHashHex, err = getTransactionHashHex(stdout); err != nil {
		return
	}
	return
}

func Invoke(conf *config.Config, inputs []string) (transactionHashHex string, err error) {
	commandArgs := []string{
		"starknet", "invoke",
		"--address", conf.VerifierAddress,
		"--abi", filepath.Join(conf.CairoDir, "build/main_abi.json"),
		"--function", "externalVerifyAdjacent",
		"--inputs"}
	commandArgs = append(commandArgs, inputs...)

	stdout, err := utils.ExecuteCommand(commandArgs, NetworkArgsForSends(conf))
	if err != nil {
		err = fmt.Errorf("starknet invoke command responded with an error: %w", err)
		return
	}

	if transactionHashHex, err = getTransactionHashHex(stdout); err != nil {
		return
	}
	return
}
