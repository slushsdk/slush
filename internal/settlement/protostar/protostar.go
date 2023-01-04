package protostar

import (
	"fmt"
	"os"
	"strings"

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

func Invoke(pConf *config.ProtostarConfig, contractAddress string, invokedFunction string, inputs []string) (transactionHashHex string, err error) {
	callArgs := "[[call]]" + "\n" +
		"type = \"invoke\" " + "\n" +
		"contract-address = " + contractAddress + "\n" +
		"function = \"" + invokedFunction + "\"" + "\n" + "inputs = "

	inputArrayString := "[ " + strings.Join(inputs, ",") + "]" + "\n" + "\n"

	callArgs = callArgs + inputArrayString

	err = Multicall(pConf, callArgs)
	return "", err
}

var currentCallNumber = 0

const callNumber = 3

func Multicall(pConf *config.ProtostarConfig, newInvoke string) (err error) {
	callsTomlPath := "./cairo/calls.toml"

	if currentCallNumber == 0 {
		if err := os.Remove(callsTomlPath); err != nil {
			return fmt.Errorf("failed to remove file: %w", err)
		}
	}

	currentCallNumber += 1

	f, err := os.OpenFile(callsTomlPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	if _, err := f.Write([]byte(newInvoke)); err != nil {
		f.Close() // ignore error; Write error takes precedence
		return fmt.Errorf("failed to write file: %w", err)

	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)

	}

	var transactionHashHex string
	fmt.Println("current call number: ", currentCallNumber)
	if currentCallNumber == callNumber {

		commandArgs := []string{
			"protostar", "--no-color", "multicall", callsTomlPath,
			"--max-fee", "auto"}

		stdout, err := utils.ExecuteCommand(commandArgs, networkArgs(pConf))
		if err != nil {
			err = fmt.Errorf("protostar invoke command responded with an error: %w", err)
			return err
		}
		// if transactionHashHex, err = getTransactionHashHex(stdout); err != nil {
		// 	return err
		// }
		fmt.Println(transactionHashHex)
		fmt.Println(string(stdout))

		currentCallNumber = 0
		return nil
	} else {
		return nil
	}

}
