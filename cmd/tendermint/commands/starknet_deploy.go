package commands

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// GenValidatorCmd allows the generation of a keypair for a
// validator.
func MakeStarknetDeployCommand() *cobra.Command {
	var privKeyPath string
	var addressPath string
	cmd := &cobra.Command{
		Use:   "starknet-deploy",
		Short: "Declare and deploy new verifier contract used for this blockchain.",
		//inputs we want to give: priv key file, account address. W
		RunE: func(cmd *cobra.Command, args []string) error {
			address, err := os.ReadFile(addressPath)
			if err != nil {
				return err
			}
			deploycmd := exec.Command("protostar", "migrate", "migrations/migration_declare_deploy.cairo", "--network", "alpha-goerli", "--private-key-path", privKeyPath, "-address", string(address), "--output-dir", "responses/", "--no-confirm")

			deploycmd.Dir = "../../tendermint-cairo"

			deploystdout, err := deploycmd.CombinedOutput()

			if err != nil {
				fmt.Println(string(deploystdout))

				return err
			}

			fmt.Println(string(deploystdout))
			return nil
		},
	}

	cmd.Flags().StringVar(&privKeyPath, "privkeypath", "",
		"Path to wallet account's private key file")
	cmd.MarkFlagRequired("privkeypath")

	cmd.Flags().StringVar(&addressPath, "addresspath", "",
		"Path to account address file")
	cmd.MarkFlagRequired("addresspath")

	return cmd
}
