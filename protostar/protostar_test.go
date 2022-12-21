package protostar

import (
	"reflect"
	"testing"

	"github.com/tendermint/tendermint/config"
)

func TestAppendKeyWithValueIfNotEmpty(t *testing.T) {
	type funcInput struct {
		args []string
		arg  string
		val  string
	}
	testCases := []struct {
		name     string
		input    funcInput
		expected []string
	}{
		0: {
			name: "empty value",
			input: funcInput{
				args: []string{"--arg1", "val1"},
				arg:  "--arg2",
				val:  "",
			},
			expected: []string{"--arg1", "val1"},
		},
		1: {
			name: "non-empty value",
			input: funcInput{
				args: []string{"--arg1", "val1"},
				arg:  "--arg2",
				val:  "val2",
			},
			expected: []string{"--arg1", "val1", "--arg2", "val2"},
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := appendKeyWithValueIfNotEmpty(tt.input.args, tt.input.arg, tt.input.val); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: appendKeyWithValueIfNotEmpty() = %v, expected %v", i, got, tt.expected)
			}
		})
	}
}

func TestNetworkArgs(t *testing.T) {
	type funcInput struct {
		conf *config.ProtostarConfig
	}
	testCases := []struct {
		name     string
		input    funcInput
		expected []string
	}{
		0: {
			name: "empty config",
			input: funcInput{
				conf: &config.ProtostarConfig{},
			},
			expected: []string{},
		},
		1: {
			name: "non-empty config",
			input: funcInput{
				conf: &config.ProtostarConfig{
					AccountAddress: "accountAddress",
					ChainId:        "chainId",
					GatewayUrl:     "gatewayURL",
					Network:        "network",
					PrivateKeyPath: "privateKeyPath",
				},
			},
			expected: []string{
				"--account-address", "accountAddress",
				"--chain-id", "chainId",
				"--gateway-url", "gatewayURL",
				"--network", "network",
				"--private-key-path", "privateKeyPath",
			},
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := networkArgs(tt.input.conf); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: networkArgs() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}

func TestExecuteCommand(t *testing.T) {
	type funcInput struct {
		pConf *config.ProtostarConfig
		args  []string
	}
	testCases := []struct {
		name     string
		input    funcInput
		expected []byte
		error    bool
		errorMsg string
	}{
		0: {
			name: "empty args",
			input: funcInput{
				pConf: &config.ProtostarConfig{},
				args:  []string{},
			},
			error:    true,
			errorMsg: "executeCommand: args must be non-empty",
		},
		1: {
			name: "echo command",
			input: funcInput{
				pConf: &config.ProtostarConfig{},
				args:  []string{"echo", "hello"},
			},
			expected: []byte("hello\n"),
		},
		2: {
			name: "echo command with network args",
			input: funcInput{
				pConf: &config.ProtostarConfig{
					AccountAddress: "accountAddress",
					ChainId:        "chainId",
					GatewayUrl:     "gatewayURL",
					Network:        "network",
					PrivateKeyPath: "privateKeyPath",
				},
				args: []string{"echo", "hello"},
			},
			expected: []byte("hello --account-address accountAddress --chain-id chainId --gateway-url gatewayURL --network network --private-key-path privateKeyPath\n"),
		},
		3: {
			name: "random not existing command",
			input: funcInput{
				pConf: &config.ProtostarConfig{},
				args:  []string{"random-not-existing-command"},
			},
			error: true,
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := executeCommand(tt.input.pConf, tt.input.args)
			if tt.error {
				if err == nil {
					t.Errorf("testCase%d failed: executeCommand() error = %v, wantErr %v", i, err, tt.error)
				}
				if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("testCase%d failed: executeCommand() error = %v, wantErr %v", i, err, tt.errorMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("testCase%d failed: executeCommand() error = %v, wantErr %v", i, err, tt.error)
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: executeCommand() = %v, want %v", i, got, tt.expected)
			}
		})
	}
}
