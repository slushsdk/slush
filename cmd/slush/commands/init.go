package commands

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	cfg "github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/internal/settlement/protostar"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmtime "github.com/tendermint/tendermint/libs/time"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
)

// InitFilesCmd initializes a fresh Tendermint Core instance.
var InitFilesCmd = &cobra.Command{
	Use:       "init [full|validator|seed]",
	Short:     "Initializes a Tendermint node",
	ValidArgs: []string{"full", "validator", "seed"},
	// We allow for zero args so we can throw a more informative error
	Args: cobra.MaximumNArgs(1),
	RunE: initFiles,
}

var (
	keyType        = "stark"
	network        string
	accountAddress string
)

func init() {
	InitFilesCmd.Flags().StringVar(&network, "network", "devnet", "Network to deploy on: testnet or devnet.")
	InitFilesCmd.Flags().StringVar(&accountAddress, "account-address", "", "Account address to use for the node.")
}

func initFiles(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("must specify a node type: slush init [validator|full|seed]")
	}
	config.Mode = args[0]

	if config.Mode == cfg.ModeValidator {
		if network != "devnet" && accountAddress == "" {
			return errors.New("must specify an account address: slush init --account-address <address>")
		}

		if err := initProtostarConfig(config, accountAddress, network); err != nil {
			return err
		}

		if err := initVerifierAddress(config, logger); err != nil {
			return err
		}
	}

	return initFilesWithConfig(config)
}

func initProtostarConfig(conf *cfg.Config, accountAddress, network string) error {
	switch network {
	case "testnet":
		conf.Protostar = &cfg.ProtostarConfig{
			AccountAddress: accountAddress,
			ChainId:        "1536727068981429685321",
			Network:        "testnet",
			PrivateKeyPath: "pkey",
		}
	case "devnet":
		fallthrough
	default:
		conf.Protostar = cfg.DefaultProtostarConfig()
	}
	err := conf.Protostar.ValidateBasic()
	if err != nil {
		return err
	}
	return nil
}

func initVerifierAddress(conf *cfg.Config, logger log.Logger) (err error) {
	classHashHex, transactionHashHex, err := protostar.Declare(logger, conf.Protostar, filepath.Join(conf.CairoDir, "build/main.json"))
	if err != nil {
		return
	}
	logger.Info(fmt.Sprintf("Successfully sent declare tx with classHash: %s and transactionHash: %s", classHashHex, transactionHashHex))

	contractAddressHex, transactionHex, err := protostar.Deploy(logger, conf.Protostar, classHashHex)
	if err != nil {
		return
	}
	logger.Info(fmt.Sprintf("Successfully sent deploy tx with contractAddress: %s and transactionHash: %s", contractAddressHex, transactionHex))

	if err != nil {
		return
	}

	conf.VerifierAddress = contractAddressHex
	return
}

func initFilesWithConfig(config *cfg.Config) error {
	var (
		pv  *privval.FilePV
		err error
	)

	if config.Mode == cfg.ModeValidator {
		// private validator
		privValKeyFile := config.PrivValidator.KeyFile()
		privValStateFile := config.PrivValidator.StateFile()
		if tmos.FileExists(privValKeyFile) {
			pv, err = privval.LoadFilePV(privValKeyFile, privValStateFile)
			if err != nil {
				return err
			}

			logger.Info("Found private validator", "keyFile", privValKeyFile,
				"stateFile", privValStateFile)
		} else {
			pv, err = privval.GenFilePV(privValKeyFile, privValStateFile, keyType)
			if err != nil {
				return err
			}
			pv.Save()
			logger.Info("Generated private validator", "keyFile", privValKeyFile,
				"stateFile", privValStateFile)
		}
	}

	nodeKeyFile := config.NodeKeyFile()
	if tmos.FileExists(nodeKeyFile) {
		logger.Info("Found node key", "path", nodeKeyFile)
	} else {
		if _, err := types.LoadOrGenNodeKey(nodeKeyFile); err != nil {
			return err
		}
		logger.Info("Generated node key", "path", nodeKeyFile)
	}

	// genesis file
	genFile := config.GenesisFile()
	if tmos.FileExists(genFile) {
		logger.Info("Found genesis file", "path", genFile)
	} else {

		genDoc := types.GenesisDoc{
			ChainID:         fmt.Sprintf("test-chain-%v", tmrand.Str(6)),
			GenesisTime:     tmtime.Now(),
			ConsensusParams: types.DefaultConsensusParams(),
		}
		if keyType == "secp256k1" {
			genDoc.ConsensusParams.Validator = types.ValidatorParams{
				PubKeyTypes: []string{types.ABCIPubKeyTypeSecp256k1},
			}
		}

		ctx, cancel := context.WithTimeout(context.TODO(), ctxTimeout)
		defer cancel()

		// if this is a validator we add it to genesis
		if pv != nil {
			pubKey, err := pv.GetPubKey(ctx)
			if err != nil {
				return fmt.Errorf("can't get pubkey: %w", err)
			}
			genDoc.Validators = []types.GenesisValidator{{
				Address: pubKey.Address(),
				PubKey:  pubKey,
				Power:   10,
			}}
		}

		if err := genDoc.SaveAs(genFile); err != nil {
			return err
		}
		logger.Info("Generated genesis file", "path", genFile)
	}

	// write config file
	if err := cfg.WriteConfigFile(config.RootDir, config); err != nil {
		return err
	}
	logger.Info("Generated config", "mode", config.Mode)

	return nil
}
