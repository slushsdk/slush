package types

import (
	fmt "fmt"

	"github.com/tendermint/tendermint/crypto/ed25519"
	"github.com/tendermint/tendermint/crypto/stark"

	"github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"github.com/tendermint/tendermint/crypto/sr25519"
)

func Ed25519ValidatorUpdate(pk []byte, power int64) ValidatorUpdate {
	pke := ed25519.PubKey(pk)

	pkp, err := encoding.PubKeyToProto(pke)
	if err != nil {
		panic(err)
	}

	return ValidatorUpdate{
		PubKey: pkp,
		Power:  power,
	}
}

func StarkValidatorUpdate(pk []byte, power int64) ValidatorUpdate {
	pkb := stark.PubKey(pk)
	pke := pkb.MakeFull()
	if pke.IsNil() {
		pkb = stark.GenPrivKeyFromSecret(pk).PubKey().(stark.PubKey)
	}
	pkp, err := encoding.PubKeyToProto(pkb)
	if err != nil {
		panic(err)
	}

	return ValidatorUpdate{
		PubKey: pkp,
		Power:  power,
	}
}

func UpdateValidator(pk []byte, power int64, keyType string) ValidatorUpdate {
	switch keyType {
	case "", stark.KeyType:
		return StarkValidatorUpdate(pk, power)
	case ed25519.KeyType:
		return Ed25519ValidatorUpdate(pk, power)
	case secp256k1.KeyType:
		pke := secp256k1.PubKey(pk)
		pkp, err := encoding.PubKeyToProto(pke)
		if err != nil {
			panic(err)
		}
		return ValidatorUpdate{
			PubKey: pkp,
			Power:  power,
		}
	case sr25519.KeyType:
		pke := sr25519.PubKey(pk)
		pkp, err := encoding.PubKeyToProto(pke)
		if err != nil {
			panic(err)
		}
		return ValidatorUpdate{
			PubKey: pkp,
			Power:  power,
		}
	default:
		panic(fmt.Sprintf("key type %s not supported", keyType))
	}
}
