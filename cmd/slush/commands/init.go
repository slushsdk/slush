package commands

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmtime "github.com/tendermint/tendermint/libs/time"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/starknet"
	"github.com/tendermint/tendermint/types"
)

// MakeInitFilesCommand returns the command to initialize a fresh Tendermint Core instance.
func MakeInitFilesCommand(conf *config.Config, logger log.Logger) *cobra.Command {
	var (
		keyType = types.DefaultValidatorParams().PubKeyTypes[0]
		network string
	)

	cmd := &cobra.Command{
		Use:       "init [full|validator|seed]",
		Short:     "Initializes a Tendermint node",
		ValidArgs: []string{"full", "validator", "seed"},
		// We allow for zero args so we can throw a more informative error
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(args) == 0 {
				err = errors.New("must specify a node type: tendermint init [validator|full|seed]")
				return
			}
			conf.Mode = args[0]

			initStarknetConfig(conf, network)
			err = initVerifierAddress(conf, logger)
			if err != nil {
				return
			}

			return initFilesWithConfig(cmd.Context(), conf, logger, keyType)
		},
	}

	cmd.Flags().StringVar(&network, "network", "devnet", "Network to deploy on: alpha-mainnet, alpha-goerli, or devnet (assumed at http://127.0.0.1:5050).")

	return cmd
}

func initStarknetConfig(conf *config.Config, network string) (err error) {
	switch network {
	case "testnet":
		conf.Starknet = &config.StarknetConfig{
			Account:          "testnet",
			AccountDir:       ".starknet_accounts",
			FeederGatewayURL: "http://127.0.0.1:5050/",
			GatewayURL:       "http://127.0.0.1:5050/",
			Network:          "alpha-goerli",
			Wallet:           "starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount",
		}
	case "testnet2":
		conf.Starknet = &config.StarknetConfig{
			Account:          "testnet2",
			AccountDir:       ".starknet_accounts",
			GatewayURL:       "https://alpha4-2.starknet.io",
			FeederGatewayURL: "https://alpha4-2.starknet.io",
			Network:          "alpha-goerli",
			Wallet:           "starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount",
		}
	case "devnet":
		fallthrough
	default:
		conf.Starknet = config.DefaultStarknetConfig()
	}
	err = conf.Starknet.ValidateBasic()
	return
}

func initVerifierAddress(conf *config.Config, logger log.Logger) (err error) {
	classHashHex, transactionHashHex, err := starknet.Declare(conf, filepath.Join(conf.CairoDir, "build/main.json"))
	if err != nil {
		return
	}
	logger.Info(fmt.Sprintf("Successfully declared with classHash=%s and transactionHash=%s", classHashHex, transactionHashHex))

	contractAddressHex, transactionHex, err := starknet.Deploy(conf, classHashHex)
	if err != nil {
		return
	}
	logger.Info(fmt.Sprintf("Successfully deployed with contractAddress=%s and transactionHash=%s", contractAddressHex, transactionHex))

	if err != nil {
		return
	}

	conf.VerifierAddress = contractAddressHex
	return
}

func initFilesWithConfig(ctx context.Context, conf *config.Config, logger log.Logger, keyType string) error {
	var (
		pv  *privval.FilePV
		err error
	)

	if conf.Mode == config.ModeValidator {
		// private validator
		privValKeyFile := conf.PrivValidator.KeyFile()
		privValStateFile := conf.PrivValidator.StateFile()
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
			if err := pv.Save(); err != nil {
				return err
			}
			logger.Info("Generated private validator", "keyFile", privValKeyFile,
				"stateFile", privValStateFile)
		}
	}

	nodeKeyFile := conf.NodeKeyFile()
	if tmos.FileExists(nodeKeyFile) {
		logger.Info("Found node key", "path", nodeKeyFile)
	} else {
		if _, err := types.LoadOrGenNodeKey(nodeKeyFile); err != nil {
			return err
		}
		logger.Info("Generated node key", "path", nodeKeyFile)
	}

	// genesis file
	genFile := conf.GenesisFile()
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

		ctx, cancel := context.WithTimeout(ctx, ctxTimeout)
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
	if err := config.WriteConfigFile(conf.RootDir, conf); err != nil {
		return err
	}
	logger.Info("Generated config", "mode", conf.Mode)

	return nil
}
