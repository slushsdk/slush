package types

import (
	"encoding/json"
	"math/big"
	"os"
)

//------------------------------------------------------------------------------
// Persistent peer ID
// TODO: encrypt on disk

// VerifierDetails is the onchain details needed for verifying a lightheader.
// It contains the nodes private key for authentication.
type VerifierDetails struct {
	PathToFiles        string         `json:"pathToFiles"`
	VerifierAddress    *big.Int       `json:"verifierAddress"`
	AccountPrivKeyPath string         `json:"accountPrivKeyPath"`
	AccountAddress     *big.Int       `json:"accountAddress"`
	NetworkDetails     NetworkDetails `json:"networkDetails"`
}

type NetworkDetails struct {
	Network      string `json:"network"`
	SeedKeysBool bool   `json:"seedKeysBool"`
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
