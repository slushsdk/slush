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
	verifierAddress     *big.Int
	verifierAbiLocation string
	accountPrivKey      *big.Int
	accountAddress      *big.Int
}

func (vd VerifierDetails) MarshalJSON() ([]byte, error) {

	return json.Marshal(vd)
}

func (vd *VerifierDetails) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, vd); err != nil {
		return err
	}
	return nil
}

// Returns the verifier's Address
func (vd VerifierDetails) VerifierAddress() *big.Int {
	return vd.verifierAddress
}

// Returns the verifier's Address
func (vd VerifierDetails) VerifierAbiLocation() string {
	return vd.verifierAbiLocation
}

// Returns the account's privkey
func (vd VerifierDetails) AccountPrivKey() *big.Int {
	return vd.accountPrivKey
}

// Returns the account's Address
func (vd VerifierDetails) AccountAddress() *big.Int {
	return vd.accountAddress
}

// SaveAs persists the VerifierDetails to filePath.
func (vd VerifierDetails) SaveAs(verifierAddressPath string, verifierAbiPath string, accountPrivKeyPath string, accountAddressPath string) error {
	jsonBytes, err := json.Marshal(vd.verifierAddress)
	if err != nil {
		return err
	}

	err = os.WriteFile(verifierAddressPath, jsonBytes, 0600)

	if err != nil {
		return err
	}

	jsonBytes, err = json.Marshal(vd.verifierAbiLocation)
	if err != nil {
		return err
	}

	err = os.WriteFile(verifierAbiPath, jsonBytes, 0600)

	if err != nil {
		return err
	}
	jsonBytes, err = json.Marshal(vd.accountPrivKey)
	if err != nil {
		return err
	}

	err = os.WriteFile(accountPrivKeyPath, jsonBytes, 0600)

	if err != nil {
		return err
	}
	jsonBytes, err = json.Marshal(vd.accountAddress)
	if err != nil {
		return err
	}

	err = os.WriteFile(accountAddressPath, jsonBytes, 0600)

	if err != nil {
		return err
	}

	return nil

}

// LoadVerifierDetails loads VerifierDetails located in filePath.
func LoadVerifierDetails(verifierAddressPath string, verifierAbiPath string, accountPrivKeyPath string, accountAddressPath string) (VerifierDetails, error) {
	jsonBytes, err := os.ReadFile(verifierAddressPath)
	if err != nil {
		return VerifierDetails{}, err
	}
	verifierAddress := big.NewInt(0)
	err = json.Unmarshal(jsonBytes, &verifierAddress)
	if err != nil {
		return VerifierDetails{}, err
	}

	jsonBytes, err = os.ReadFile(verifierAbiPath)
	if err != nil {
		return VerifierDetails{}, err
	}
	verifierAbiLocation := ""
	err = json.Unmarshal(jsonBytes, &verifierAbiLocation)
	if err != nil {
		return VerifierDetails{}, err
	}

	jsonBytes, err = os.ReadFile(accountPrivKeyPath)
	if err != nil {
		return VerifierDetails{}, err
	}
	accountPrivKey := big.NewInt(0)
	err = json.Unmarshal(jsonBytes, &accountPrivKey)
	if err != nil {
		return VerifierDetails{}, err
	}

	jsonBytes, err = os.ReadFile(accountAddressPath)
	if err != nil {
		return VerifierDetails{}, err
	}
	accountAddress := big.NewInt(0)
	err = json.Unmarshal(jsonBytes, &accountAddress)
	if err != nil {
		return VerifierDetails{}, err
	}

	veriferDetails := VerifierDetails{verifierAddress, verifierAbiLocation, accountAddress, accountPrivKey}
	return veriferDetails, nil
}
