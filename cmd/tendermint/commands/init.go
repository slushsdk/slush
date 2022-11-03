package commands

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/tendermint/tendermint/config"
	"github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmtime "github.com/tendermint/tendermint/libs/time"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/smartcontracts"
	"github.com/tendermint/tendermint/types"
)

// MakeInitFilesCommand returns the command to initialize a fresh Tendermint Core instance.
func MakeInitFilesCommand(conf *config.Config, logger log.Logger) *cobra.Command {
	var keyType string
	var pathToFiles string
	var network string
	var devnetbool string

	cmd := &cobra.Command{
		Use:       "init [full|validator|seed]",
		Short:     "Initializes a Tendermint node",
		ValidArgs: []string{"full", "validator", "seed"},
		// We allow for zero args so we can throw a more informative error
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("must specify a node type: tendermint init [validator|full|seed]")
			}
			conf.Mode = args[0]

			var b bool
			if devnetbool == "1" {
				b = true
			} else {
				b = false

			}
			ret, err := smartcontracts.DeclareDeploy(pathToFiles, network, b)

			if err != nil {
				fmt.Println(string(ret))
				fmt.Println(err)
				return err
			}
			logger.Info("Successfully declared and deployed contract at:...")
			line := regexp.MustCompile(`contract_address *.*?\n`)
			zerox := regexp.MustCompile(`0x.{64}`)
			fmt.Printf("%q\n", (line.Find(ret)))
			fmt.Printf("%q\n", zerox.Find(line.Find(ret)))

			return initFilesWithConfig(cmd.Context(), conf, logger, keyType)

		},
	}

	cmd.Flags().StringVar(&keyType, "key", types.ABCIPubKeyTypeStark,
		"Key type to generate privval file with. Options: stark, ed25519, secp256k1")

	cmd.Flags().StringVar(&pathToFiles, "path-to-files", "",
		"For mainnet or testnet: relative path to folder storing wallet account's private key file and address file, stored as pkey and address stored as hex without leading 0x. ")

	cmd.Flags().StringVar(&network, "network", "alpha-goerli",
		"Network to deploy on: alpha-mainnet, alpha-goerli, or devnet (assumed at http://127.0.0.1:5050). If using devnet either provide keys, or launch devnet using seed=42.")
	cmd.MarkFlagRequired("network")

	cmd.Flags().StringVar(&devnetbool, "devnetbool", "1",
		"If using devnet either provide keys (default), or launch devnet using seed=42 and set --devnetbool=1.")

	return cmd
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
