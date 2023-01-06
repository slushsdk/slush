package protostar

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/internal/settlement/starknet"
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

func starknetConfigFromProtostarForGetTransaction(pConf *config.ProtostarConfig) (sConfig *config.StarknetConfig) {
	sConf := config.DefaultStarknetConfig()

	sConf.FeederGatewayURL = pConf.GatewayUrl
	sConf.GatewayURL = pConf.GatewayUrl
	sConf.Network = pConf.Network

	return sConf
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

func getMulticallTxHashFelt(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^transaction hash: (0x[A-Fa-f0-9]*$)`, "multicall transaction hash")(rawStdout)
}

func Declare(pConf *config.ProtostarConfig, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"protostar", "--no-color", "declare", contractPath, "--max-fee", "auto", "--wait-for-acceptance"}

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
	commandArgs := []string{"protostar", "--no-color", "deploy", classHashHex, "--max-fee", "auto", "--wait-for-acceptance"}

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

	AddInvokeToFile(callArgs)
	Multicall(pConf)
	return "", err
}

var currentCallNumber = 0

const maxCallNumber = 50

// this file is created and used here, so there is no need to store location in config, I think?
const callsTomlPath = "./cairo/calls.toml"

func AddInvokeToFile(newInvoke string) (err error) {

	// if we have no calls, we can remove the file. This also clears it if not empty, e.g. on startup.
	if currentCallNumber == 0 {
		if err := os.WriteFile(callsTomlPath, []byte{}, 0644); err != nil {
			return fmt.Errorf("failed to clear file: %w", err)
		}
	}

	currentCallNumber += 1

	// opening and writing to file
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
	return nil
}

func Multicall(pConf *config.ProtostarConfig) (err error) {
	// if we need to send the transaction, we should send it.
	if currentCallNumber == maxCallNumber {

		commandArgs := []string{
			"protostar", "--no-color", "multicall", callsTomlPath,
			"--max-fee", "auto"}

		fmt.Println("sending multicall")

		transactionHash, err := SendMulticall(commandArgs, pConf)

		if err != nil {
			fmt.Println("sending multicall failed!")
		}
		QueryTxUntilAccepted(transactionHash, commandArgs, pConf)

		currentCallNumber = 0
		return nil
	}

	return nil
}

func SendMulticall(commandArgs []string, pConf *config.ProtostarConfig) (txhash string, err error) {
	stdout, err := utils.ExecuteCommand(commandArgs, networkArgs(pConf))
	if err != nil {
		fmt.Println("error sending multicall: ", err)
		err = fmt.Errorf("protostar multicall command responded with an error: %w", err)
		return "", err
	}
	fmt.Println("multicall sent")

	transactionHash, err := getMulticallTxHashFelt(stdout)
	if err != nil {
		return "", err
	}

	fmt.Println(string(stdout))
	fmt.Println(transactionHash)
	return transactionHash, nil
}

func QueryTxUntilAccepted(txHash string, multicallCommandArgs []string, pConf *config.ProtostarConfig) (err error) {
	txAcceptedOrRejected := false
	fmt.Println("starting to query transactions")
	for !txAcceptedOrRejected {
		time.Sleep(5 * time.Second)
		// query the transaction
		commandArgs := []string{"starknet", "get_transaction", "--hash", txHash}

		stdout, err := utils.ExecuteCommand(commandArgs, starknet.NetworkArgsForGetTransaction(starknetConfigFromProtostarForGetTransaction(pConf)))
		if err != nil {
			err = fmt.Errorf("get transaction command responded with an error: %w", err)
			return err
		}

		if strings.Contains(string(stdout), "\"status\": \"ACCEPTED_ON_L2\"") {
			txAcceptedOrRejected = true
			fmt.Println("Transaction is accepted")
		} else if strings.Contains(string(stdout), "\"status\": \"REJECTED\"") {
			// failure happens normally because of gas fees. We should retry.

			txAcceptedOrRejected = true
			fmt.Println("Transaction is rejected retrying:")
			txHash, err = SendMulticall(multicallCommandArgs, pConf)
			if err != nil {
				break
			}
		} else {
			fmt.Println("Transaction is still pending")
		}
		fmt.Println(string(stdout))
	}
	return err
}
