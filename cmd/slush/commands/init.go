package commands

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/spf13/cobra"

	cfg "github.com/tendermint/tendermint/config"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	tmtime "github.com/tendermint/tendermint/libs/time"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/smartcontracts"
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
	keyType = types.DefaultValidatorParams().PubKeyTypes[0]
	network string
	pkey    string
	address string
)

func init() {

	InitFilesCmd.Flags().StringVar(&network, "network", "devnet",
		"Network to deploy on: alpha-mainnet, alpha-goerli, or devnet (assumed at http://127.0.0.1:5050). If using devnet either provide keys, or launch devnet using --seed=42, and set seedkeys=1 here.")
	InitFilesCmd.MarkFlagRequired("network")

	InitFilesCmd.Flags().StringVar(&pkey, "pkey", "0", "Specify privatekey. Not needed if --seedkeys=1. ")

	InitFilesCmd.Flags().StringVar(&address, "address", "0", "Specify address. Not needed if --seedkeys=1. ")

	InitFilesCmd.Flags().StringVar(&seedkeys, "seedkeys", "0",
		"If using devnet either provide keys (default), or launch devnet using seed=42 and set --seedkeys=1.")

}

func initFiles(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return errors.New("must specify a node type: tendermint init [validator|full|seed]")
	}
	config.Mode = keyType

	vd, err := InitializeVerifierDetails(pkey, address, network) //will probably have to use args[i] here
	if err != nil {
		return err
	}

	verifierAddress, class, err := smartcontracts.DeclareDeploy(vd, conf.VerifierDetailsFile())

	if err != nil {
		return err
	}

	logger.Info("Successfully declared with classhash: ", class.Text(16), "")
	logger.Info("and deployed contract address:", verifierAddress.Text(16), "")

	return initFilesWithConfig(config)
}

func InitializeVerifierDetails(pkeyStr string, addressStr string, network string) (types.VerifierDetails, error) {

	address, b := big.NewInt(0).SetString(addressStr, 16)
	if !b {
		return types.VerifierDetails{}, errors.New("could not read address string. Provide in hex, without leading 0x")
	}

	pkey, b := big.NewInt(0).SetString(pkeyStr, 16)
	if !b {
		return types.VerifierDetails{}, errors.New("could not read pkey string. Provide in hex, without leading 0x")
	}

	// Check whether we need to use burnt in keys.
	var seedKeysBool bool
	if pkeyStr == "0" || addressStr == "0" {
		seedKeysBool = true
	} else {
		seedKeysBool = false

	}

	pkeypath := "pkey"

	if network == "devnet" && seedKeysBool {
		pkeypath = "seed42pkey"
		err := os.WriteFile("cairo/"+pkeypath, []byte("bdd640fb06671ad11c80317fa3b1799d"), 0644)
		if err != nil {
			return types.VerifierDetails{}, err
		}
		address, b = big.NewInt(0).SetString("347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a", 16)
		if !b {
			return types.VerifierDetails{}, errors.New("could not read baked in address string. ")
		}

	} else {

		if pkey.Cmp(big.NewInt(0)) != 0 {
			err := os.WriteFile("cairo/"+pkeypath, []byte(pkeyStr), 0644)
			if err != nil {
				return types.VerifierDetails{}, err
			}
		} else {
			return types.VerifierDetails{}, errors.New("if not on devnet or seedkeys != 1 then pkey needs to be provided and nonzero. Input with --pkey  flag in hex, without leading 0x")
		}

		if address.Cmp(big.NewInt(0)) == 0 {
			return types.VerifierDetails{}, errors.New("if not on devnet or seedkeys != 1 then address needs to be provided and nonzero. Input with --address  flag in hex, without leading 0x")
		}
	}

	nd := types.NetworkDetails{Network: network, SeedKeysBool: seedKeysBool}
	vd := types.VerifierDetails{AccountPrivKeyPath: pkeypath, AccountAddress: address, NetworkDetails: nd}

	return vd, nil
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
