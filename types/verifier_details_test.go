package types_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tendermint/tendermint/types"
)

func TestNewVerifierDetails(t *testing.T) {
	type input struct {
		accountAddress        string
		accountPrivateKeyPath string
		network               string
		verifierAddress       string
	}
	type testCase struct {
		description string
		inp         input
		expected    types.VerifierDetails
		err         string
	}
	tcs := []testCase{
		0: {
			description: "simple input",
			inp: input{
				accountAddress:        "0000000000000000000000000000000000000000",
				accountPrivateKeyPath: "ha",
				network:               "he",
				verifierAddress:       "0000000000000000000000000000000000000000",
			},
			expected: types.VerifierDetails{
				AccountAddress:        big.NewInt(0),
				AccountPrivateKeyPath: "ha",
				Network:               "he",
				VerifierAddress:       big.NewInt(0),
			},
		},
		1: {
			description: "invalid account address format, with 0x prefix",
			inp: input{
				accountAddress:        "0x000000000000000000000000000000000000000",
				accountPrivateKeyPath: "",
				network:               "",
				verifierAddress:       "0000000000000000000000000000000000000000",
			},
			expected: types.VerifierDetails{},
			err:      `could not read account address string: "0x000000000000000000000000000000000000000", it should be in hex, without leading 0x`,
		},
		2: {
			description: "invalid account address format with non hex input",
			inp: input{
				accountAddress:        "000000000000000000000000000000000000000g",
				accountPrivateKeyPath: "",
				network:               "",
				verifierAddress:       "0000000000000000000000000000000000000000",
			},
			expected: types.VerifierDetails{},
			err:      `could not read account address string: "000000000000000000000000000000000000000g", it should be in hex, without leading 0x`,
		},
		3: {
			description: "invalid verifier address format, with 0x prefix",
			inp: input{
				accountAddress:        "0000000000000000000000000000000000000000",
				accountPrivateKeyPath: "",
				network:               "",
				verifierAddress:       "0x000000000000000000000000000000000000000",
			},
			expected: types.VerifierDetails{},
			err:      `could not read verifier address string: "0x000000000000000000000000000000000000000", it should be in hex, without leading 0x`,
		},
		4: {
			description: "invalid verifier address format with non hex input",
			inp: input{
				accountAddress:        "0000000000000000000000000000000000000000",
				accountPrivateKeyPath: "",
				network:               "",
				verifierAddress:       "000000000000000000000000000000000000000g",
			},
			expected: types.VerifierDetails{},
			err:      `could not read verifier address string: "000000000000000000000000000000000000000g", it should be in hex, without leading 0x`,
		},
	}

	for i, tc := range tcs {
		t.Run(tc.description, func(t *testing.T) {
			vd, err := types.NewVerifierDetails(tc.inp.accountAddress, tc.inp.accountPrivateKeyPath, tc.inp.network, tc.inp.verifierAddress)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err, "test case %d: %s failed, expected error: %v", i, tc.description, tc.err)
			} else {
				require.NoError(t, err, "test case %d: %s failed, expected no error", i, tc.description)
				require.Equal(t, tc.expected, vd, "test case %d: %s failed, expected %v, got %v", i, tc.description, tc.expected, vd)
			}
		})
	}
}

func TestVerifierDetailsSaveAs(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "vd.json")
	require.NoFileExists(t, filePath)

	vd := types.VerifierDetails{}
	require.NoError(t, vd.SaveAs(filePath))
	require.FileExists(t, filePath)
}

func TestLoadVerifierDetails(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "vd.json")

	_, err := types.LoadVerifierDetails(filePath)
	require.True(t, os.IsNotExist(err))

	vd1, err := types.NewVerifierDetails("0000000000000000000000000000000000000000", "ha", "he", "0000000000000000000000000000000000000000")
	require.NoError(t, err)
	require.NoError(t, vd1.SaveAs(filePath))

	vd2, err := types.LoadVerifierDetails(filePath)
	require.NoError(t, err)
	require.NotNil(t, vd2)
	require.Equal(t, vd1, vd2)
}
