package types

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

//------------------------------------------------------------------------------
// Persistent peer ID
// TODO: encrypt on disk

// VerifierDetails is the onchain details needed for verifying a lightheader.
// It contains the nodes private key for authentication.
type VerifierDetails struct {
	AccountAddress        *big.Int `json:"accountAddress"`
	AccountPrivateKeyPath string   `json:"accountPrivateKeyPath"`
	Network               string   `json:"network"`
	VerifierAddress       *big.Int `json:"verifierAddress"`
}

func NewVerifierDetails(accountAddress, accountPrivateKeyPath, network, verifierAddress string) (vd VerifierDetails, err error) {
	accountAddressBigInt, ok := new(big.Int).SetString(accountAddress, 16)
	if !ok {
		err = fmt.Errorf(`could not read account address string: "%s", it should be in hex, without leading 0x`, accountAddress)
		return
	}

	verifierAddressBigInt, ok := new(big.Int).SetString(verifierAddress, 16)
	if !ok {
		err = fmt.Errorf(`could not read verifier address string: "%s", it should be in hex, without leading 0x`, verifierAddress)
		return
	}

	vd = VerifierDetails{
		AccountPrivateKeyPath: accountPrivateKeyPath,
		AccountAddress:        accountAddressBigInt,
		Network:               network,
		VerifierAddress:       verifierAddressBigInt,
	}
	return
}

// SaveAs persists the VerifierDetails to filePath.
func (vd VerifierDetails) SaveAs(verifierDetailsPath string) error {
	jsonBytes, err := json.Marshal(vd)
	if err != nil {
		return err
	}

	err = os.WriteFile(verifierDetailsPath, jsonBytes, 0600)

	if err != nil {
		return err
	}

	return nil

}

// LoadVerifierDetails loads VerifierDetails located in filePath.
func LoadVerifierDetails(verifierDetailsPath string) (VerifierDetails, error) {
	jsonBytes, err := os.ReadFile(verifierDetailsPath)
	if err != nil {
		return VerifierDetails{}, err
	}

	var vd VerifierDetails
	err = json.Unmarshal(jsonBytes, &vd)

	if err != nil {
		return VerifierDetails{}, err
	}

	return vd, nil

}
