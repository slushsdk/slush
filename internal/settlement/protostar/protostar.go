package protostar

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"

	"github.com/tendermint/tendermint/internal/settlement/parser"
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

func starknetNetworkArgs(pConf *config.ProtostarConfig) (networkArgs []string) {
	network := pConf.Network
	if pConf.Network == "testnet" {
		network = "alpha-goerli"
	}
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--gateway_url", pConf.GatewayUrl)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--feeder_gateway_url", pConf.GatewayUrl)
	networkArgs = utils.AppendKeyWithValueIfNotEmpty(networkArgs, "--network", network)
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

func getMulticallTxHashFelt(rawStdout []byte) (string, error) {
	return utils.RegexFunctionFactory(`(?m)^transaction hash: (0x[A-Fa-f0-9]*$)`, "multicall transaction hash")(rawStdout)
}

func Declare(logger log.Logger, pConf *config.ProtostarConfig, contractPath string) (classHashHex, transactionHashHex string, err error) {
	commandArgs := []string{"protostar", "--no-color", "declare", contractPath, "--max-fee", "auto", "--wait-for-acceptance"}

	stdout, err := ExecuteCommandUntilNoGasFeeError(logger, commandArgs, networkArgs(pConf), "declare")
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

func Deploy(logger log.Logger, pConf *config.ProtostarConfig, classHashHex string) (contractAddressHex, transactionHashFelt string, err error) {
	commandArgs := []string{"protostar", "--no-color", "deploy", classHashHex, "--max-fee", "auto", "--wait-for-acceptance"}

	stdout, err := ExecuteCommandUntilNoGasFeeError(logger, commandArgs, networkArgs(pConf), "deploy")
	if err != nil {
		err = fmt.Errorf("protostar deploy command responded with an error:\n%s", err)
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

// we cant use this for multicall, as that does not have a wait-for-acceptance flag. Check if it has been added, if so use it.
func ExecuteCommandUntilNoGasFeeError(logger log.Logger, commandArgs, networkArgs []string, commandNameForPrinting string) ([]byte, error) {
	commandExecutedOrNotGasError := false
	var stdout []byte
	var err error
	for !commandExecutedOrNotGasError {
		stdout, err = utils.ExecuteCommand(commandArgs, networkArgs)

		if (err != nil) && (strings.Contains(err.Error(), "Actual fee exceeded max fee")) {
			logger.Info("protostar "+commandNameForPrinting+" command responded a max fee error, trying again %w", err)

		} else {
			commandExecutedOrNotGasError = true
		}
	}
	return stdout, err
}

func Invoke(logger log.Logger, pConf *config.ProtostarConfig, contractAddress string, invokedFunction string, inputs parser.SettlementData) (err error) {
	callArgs := "[[call]]" + "\n" +
		"type = \"invoke\" " + "\n" +
		"contract-address = " + contractAddress + "\n" +
		"function = \"" + invokedFunction + "\"" + "\n" + "inputs = "

	inputArrayString := "[ " + strings.Join(inputs.Data, ",") + "]" + "\n" + "\n"

	callArgs = callArgs + inputArrayString
	logger.Info("block recorded for settlement")
	err = AddInvokeToFile(logger, callArgs)
	if err != nil {
		return err
	}
	err = Multicall(logger, pConf, inputs)
	if err != nil {
		return
	}
	return nil
}

const maxCallNumber = 10

var currentMulticallNumber = 0
var numberOfCalls = []uint32{0}
var callsTomlPath string

func AddInvokeToFile(logger log.Logger, newInvoke string) (err error) {
	if currentMulticallNumber == 0 && numberOfCalls[currentMulticallNumber] == 0 {
		if pwd, _ := os.Getwd(); pwd == "/slush" {
			nodeNum := os.Getenv("ID")
			callsTomlPath = "/slush/node" + nodeNum + "/data/multicalls"
		} else {
			callsTomlPath = "./valdata/data/multicalls"
		}
		if err := os.Mkdir(callsTomlPath, config.DefaultDirPerm); err != nil {
			return fmt.Errorf("failed to make directory: %w", err)
		}

	}
	// if we have no calls, we can remove the file. This also clears it if not empty
	if numberOfCalls[currentMulticallNumber] == 0 {
		if err := os.WriteFile(callsTomlPath+"/call"+fmt.Sprint(currentMulticallNumber)+".toml", []byte{}, 0777); err != nil {
			return fmt.Errorf("failed to clear file: %w", err)
		}
	}

	numberOfCalls[currentMulticallNumber] += 1

	// opening and writing to file
	f, err := os.OpenFile(callsTomlPath+"/call"+fmt.Sprint(currentMulticallNumber)+".toml", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
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

func Multicall(logger log.Logger, pConf *config.ProtostarConfig, sData parser.SettlementData) (err error) {
	// if we need to send the transaction, we should send it.

	if numberOfCalls[currentMulticallNumber] == maxCallNumber {
		thisMulticallNumber := currentMulticallNumber
		currentMulticallNumber += 1
		numberOfCalls = append(numberOfCalls, 0)
		if sData.ValidatorAddress == sData.CommitmentProposer {
			commandArgs := []string{
				"protostar", "--no-color", "multicall", callsTomlPath + "/call" + fmt.Sprint(thisMulticallNumber) + ".toml",
				"--max-fee", "auto"}

			logger.Info("Sending multicall to starknet")

			err = ExecuteUntilNoGasErrorReplacement(logger, commandArgs, pConf)
			if err != nil {
				return fmt.Errorf("error querying tx until accepted error: %w", err)
			}
		}

		return nil
	}

	return nil
}

// we don't have waitforacceptance for multicall, so we query if the tx is accepted/rejected and has tx fee error, if yes we retry. If it is a proper error, we don't.
func ExecuteUntilNoGasErrorReplacement(logger log.Logger, multicallCommandArgs []string, pConf *config.ProtostarConfig) (err error) {
	txHash, err := SendMulticall(logger, multicallCommandArgs, pConf)

	if err != nil {
		return fmt.Errorf("sending multicall failed: %w", err)
	}

	txAcceptedOrRejected := false
	i := 0
	for !txAcceptedOrRejected {
		i++
		time.Sleep(5 * time.Second)
		// query the transaction
		commandArgs := []string{"starknet", "get_transaction", "--hash", txHash}

		stdout, err := utils.ExecuteCommand(commandArgs, starknetNetworkArgs(pConf))
		if err != nil {
			return fmt.Errorf("get transaction command responded with an error: %w", err)
		}

		if strings.Contains(string(stdout), "\"status\": \"ACCEPTED_ON_L2\"") {
			txAcceptedOrRejected = true
			logger.Info("Transaction is accepted")
		} else if strings.Contains(string(stdout), "Actual fee exceeded max fee") {

			logger.Info("Transaction had gas error, retrying:")
			txHash, err = SendMulticall(logger, multicallCommandArgs, pConf)
			if err != nil {
				return err
			}
		} else if strings.Contains(string(stdout), "\"status\": \"REJECTED\"") {
			txAcceptedOrRejected = true
			logger.Info("Transaction failed with error:", string(stdout))
			txHash, err = SendMulticall(logger, multicallCommandArgs, pConf)
			if err != nil {
				break
			}
		} else {
			logger.Info("Transaction is still pending")
		}
	}
	return err
}

func SendMulticall(logger log.Logger, commandArgs []string, pConf *config.ProtostarConfig) (txhash string, err error) {
	stdout, err := utils.ExecuteCommand(commandArgs, networkArgs(pConf))
	if err != nil {
		logger.Info("protostar error had output: ", string(stdout))
		err = fmt.Errorf("protostar multicall command responded with an error: %w", err)
		return "", err
	}

	transactionHash, err := getMulticallTxHashFelt(stdout)
	if err != nil {
		return "", err
	}

	return transactionHash, nil
}
