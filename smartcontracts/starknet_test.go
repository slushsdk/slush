package smartcontracts_test

import (
	"encoding/json"
	"io/fs"
	"math/big"
	"os"
	"testing"

	"github.com/tendermint/tendermint/internal/consensus"
	"github.com/tendermint/tendermint/smartcontracts"
	"github.com/tendermint/tendermint/types"
)

func TestDeclare(t *testing.T) {
	smartcontracts.DeclareDeploy()
}

func TestInvoke(t *testing.T) {
	trustedLightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"2","time":"2022-10-14T13:24:31.520445159Z","last_block_id":{"hash":"05C32CDC85F91A5985E8B677F4E66BF9E2E6AD81C3EF78631A3C261FF66B0CBF","parts":{"total":1,"hash":"06A26A085152107697F0ECFE8A03E98DD359F7704CF4180A8372DE9D97A2FFC1"}},"last_commit_hash":"04454198E80175870CDA3A3C01E19188A485AC6D5D786D58865577BE3737F34A","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","next_validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E"},"commit":{"height":"2","round":0,"block_id":{"hash":"048DC96483670246BECAF0EDACCC3E9E8A56EDEFC3E2BE2D5CB74897BAEAC67C","parts":{"total":1,"hash":"02E4528C17BF48E6612B6A7FBB2EE554EDF5F3DB00CFD124369BC20E19716327"}},"signatures":[{"block_id_flag":2,"validator_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E","timestamp":"2022-10-14T13:24:37.127453388Z","signature":"BA4U7G4bat7vjxHWZVtZNTOUIl88gAqP4Xzw9LzSRzwD26wQed88+841SxS3IDA7NX+JECv1QuE0p6aABVUhog=="}]}},"canonical":false}`
	untrustedLightBlockString := `{"signed_header":{"header":{"version":{"block":"11","app":"1"},"chain_id":"test-chain-IrF74Y","height":"3","time":"2022-10-14T13:24:44.50752585Z","last_block_id":{"hash":"048DC96483670246BECAF0EDACCC3E9E8A56EDEFC3E2BE2D5CB74897BAEAC67C","parts":{"total":1,"hash":"02E4528C17BF48E6612B6A7FBB2EE554EDF5F3DB00CFD124369BC20E19716327"}},"last_commit_hash":"0107550A529CAAD7A9438FB11E5528602B63BC83418713DD2B09FA7E30C626DD","data_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","next_validators_hash":"06424BDF5299B41922D5FC97DE1D4EE3C4072D2EB0D4904F8F44452E978C3B6A","consensus_hash":"04B6EE42C4CB17A4129A2B6135C8FB4B6CBA7A5F9A18B87C4EFEFB74F2F0F24E","app_hash":"0000000000000000000000000000000000000000000000000000000000000000","last_results_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","evidence_hash":"049EE3EBA8C1600700EE1B87EB599F16716B0B1022947733551FDE4050CA6804","proposer_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E"},"commit":{"height":"3","round":0,"block_id":{"hash":"01159AAF5196DB2F20D9E99A4367EE93465226AF348162652061E19E32803F1B","parts":{"total":1,"hash":"03B70ED423A9D39E956967F49CE3228FDEEB4F6982383FED18BCD2DB755E5B34"}},"signatures":[{"block_id_flag":2,"validator_address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E","timestamp":"2022-10-14T13:24:49.554053779Z","signature":"B/ikqqI3zPMbl5bzJFzQ8s1l7dEwW7DJ9w97gL70Qs4G7WzxArvNYItwQ3Gy5XnDT4/zh3tEWfWbFq8JV50mDQ=="}]}},"canonical":false}`
	validatorSetString := `{"block_height":"3","validators":[{"address":"00BDFC2A72D8828A45531126520BF5F981434D95922DC2867857874FA9966B0E","pub_key":{"type":"tendermint/PubKeyStark","value":"B19CsyMnLUkCfXu4joziTCOhJexv/O5tIwBLXV5Rs9kGAbRLvgQAW3Id24QbxGGxcOWxDEba43ykDQGgv2+wBQ=="},"voting_power":"10","proposer_priority":"0"}],"count":"1","total":"1"}`

	var validatorSet types.ValidatorSet
	json.Unmarshal([]byte(validatorSetString), &validatorSet)
	validatorSet.Proposer = validatorSet.Validators[0]

	var trustedLightBlock, untrustedLightBlock types.LightBlock
	json.Unmarshal([]byte(trustedLightBlockString), &trustedLightBlock)
	json.Unmarshal([]byte(untrustedLightBlockString), &untrustedLightBlock)

	trustingPeriod, _ := big.NewInt(0).SetString("99999999999999999999", 10)

	ext := consensus.FormatExternal(trustedLightBlock, untrustedLightBlock, &validatorSet, big.NewInt(1665753884507526850), big.NewInt(10), trustingPeriod)
	jsonString, _ := json.Marshal(ext)

	err := os.WriteFile("../../tendermint-cairo/invoke_input.json", jsonString, fs.FileMode(0644))

	if(err != nil) {
		t.Error(err)
	}

	vd := types.VerifierDetails{}
	smartcontracts.Invoke(vd)
}
