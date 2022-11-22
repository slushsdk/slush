package smartcontracts_test

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/tendermint/tendermint/internal/consensus"
	"github.com/tendermint/tendermint/smartcontracts"
	"github.com/tendermint/tendermint/types"
)

func TestDeclare(t *testing.T) {
	// Todo: fill this out
	//  smartcontracts.DeclareDeploy()
}

func TestInvoke(t *testing.T) {
	trustedLightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-11-04T17:43:45.220479Z","last_block_id":{"hash":"038E1EFB6F2C0B4AA1051C0A9B4494B0A7CF34D81C76E6C161B164249A660ABF","parts":{"total":1,"hash":"06A9F404CEC26739C0E7FBDC46DAC64B9151D3A14FA4BB8B4DFD1785D3B14C15"}},"last_commit_hash":"06BE053E669912201CFE99C43884AB9AC38713AC888873B375588A4C401428F6","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"0241C0593DCFA3154B864E19E3AB6C03D2B79181BE7DC6565C9B6C68EA4D47F6","next_validators_hash":"0241C0593DCFA3154B864E19E3AB6C03D2B79181BE7DC6565C9B6C68EA4D47F6","consensus_hash":"00848270D575B49884653D7B3ED720EB84CE99D064D3BD3210FE23BFB811CB66","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"06EBC607235127FDABA1DB1A9CE71A34E7B880084F7188B03E7A3A1F0334DDBD"},"commit":{"height":"2","round":0,"block_id":{"hash":"048A972F4E947BBBF4E9E0AF350AD233EC6E394903728B3D3F8488F168915C16","parts":{"total":1,"hash":"04A7BCD4D5AEED5C99B3530549E83C7DACA49102542B20E28C48FBD0E911A622"}},"signatures":[{"block_id_flag":2,"validator_address":"06EBC607235127FDABA1DB1A9CE71A34E7B880084F7188B03E7A3A1F0334DDBD","timestamp":"2022-11-04T17:43:46.755686Z","signature":"BWkRvub8iP9VltjYMrfDekOL/0WjijYEIUjbkVnSntQDMU0B4izOLRPcJqub0t0AHyDPCOvx+4w14gdeKSxfmQ=="}]}},"canonical":false}`
	untrustedLightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-11-04T17:43:48.879554Z","last_block_id":{"hash":"048A972F4E947BBBF4E9E0AF350AD233EC6E394903728B3D3F8488F168915C16","parts":{"total":1,"hash":"04A7BCD4D5AEED5C99B3530549E83C7DACA49102542B20E28C48FBD0E911A622"}},"last_commit_hash":"03DEA59253B9502F1AEDEA3A4FADFFB57C3229266AA8601BCEC23BA292D5A347","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"0241C0593DCFA3154B864E19E3AB6C03D2B79181BE7DC6565C9B6C68EA4D47F6","next_validators_hash":"0241C0593DCFA3154B864E19E3AB6C03D2B79181BE7DC6565C9B6C68EA4D47F6","consensus_hash":"00848270D575B49884653D7B3ED720EB84CE99D064D3BD3210FE23BFB811CB66","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"06EBC607235127FDABA1DB1A9CE71A34E7B880084F7188B03E7A3A1F0334DDBD"},"commit":{"height":"3","round":0,"block_id":{"hash":"03054DF71090EE602E6C0A433B949B726DC20719BD8448E281679A4F78810B7B","parts":{"total":1,"hash":"0424FD36683BB2F85C88BF098088937769FD788C422E63D66714F939F7E77FB9"}},"signatures":[{"block_id_flag":2,"validator_address":"06EBC607235127FDABA1DB1A9CE71A34E7B880084F7188B03E7A3A1F0334DDBD","timestamp":"2022-11-04T17:43:50.41826Z","signature":"BC6w1ASm4R4jq2or6mjD2ROgaYr4WcAT2GskhCOcPQIGXVoVV7JfLXnRsQEaPSjmtjr4ZIOt06InimmziDjqTw=="}]}},"canonical":true}`
	validatorSetString := `{"block_height":"3","validators":[{"address":"06EBC607235127FDABA1DB1A9CE71A34E7B880084F7188B03E7A3A1F0334DDBD","pub_key":{"type":"tendermint/PubKeyStark","value":"AHzA3ABEpcfPL3+Zfmdm4fGb1MBih2zMt0m1iyqS5KsAoJVUlan320a55nvQrj1ilGjRDSPZqeaLyKbEe6KT3g=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`

	var validatorSet types.ValidatorSet
	json.Unmarshal([]byte(validatorSetString), &validatorSet)
	validatorSet.Proposer = validatorSet.Validators[0]

	var trustedLightBlock, untrustedLightBlock types.LightBlock
	json.Unmarshal([]byte(trustedLightBlockString), &trustedLightBlock)
	json.Unmarshal([]byte(untrustedLightBlockString), &untrustedLightBlock)

	curtime := big.NewInt(1665753884507526850)

	verifieraddress, _ := big.NewInt(0).SetString("2681321777313866831207172647830701585786458434608807373285616162347166442907", 10)
	address, _ := big.NewInt(0).SetString("347be35996a21f6bf0623e75dbce52baba918ad5ae8d83b6f416045ab22961a", 16)

	os.WriteFile("cairo/seed42pkey", []byte("bdd640fb06671ad11c80317fa3b1799d"), 0644)

	vd := types.VerifierDetails{VerifierAddress: verifieraddress, AccountPrivateKeyPath: "./seed42pkey", AccountAddress: address, Network: "devnet"}
	id := consensus.InvokeData{TrustedLightB: trustedLightBlock, UntrustedLightB: untrustedLightBlock, ValidatorSet: validatorSet}

	smartcontracts.InvokePath(vd, id, curtime, "../cairo/migrations")
}
