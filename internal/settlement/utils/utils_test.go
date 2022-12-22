package utils

import (
	"reflect"
	"testing"
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
			if got := AppendKeyWithValueIfNotEmpty(tt.input.args, tt.input.arg, tt.input.val); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("testCase%d failed: appendKeyWithValueIfNotEmpty() = %v, expected %v", i, got, tt.expected)
			}
		})
	}
}

func TestExecuteCommand(t *testing.T) {
	type funcInput struct {
		args        []string
		networkArgs []string
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
				args: []string{},
			},
			error:    true,
			errorMsg: "executeCommand: args must be non-empty",
		},
		1: {
			name: "echo command",
			input: funcInput{
				args: []string{"echo", "hello"},
			},
			expected: []byte("hello\n"),
		},
		2: {
			name: "echo command with network args",
			input: funcInput{
				args: []string{"echo", "hello"},
				networkArgs: []string{
					"--account-address", "accountAddress",
					"--chain-id", "chainId",
					"--gateway-url", "gatewayURL",
					"--network", "network",
					"--private-key-path privateKeyPath",
				},
			},
			expected: []byte("hello --account-address accountAddress --chain-id chainId --gateway-url gatewayURL --network network --private-key-path privateKeyPath\n"),
		},
		3: {
			name: "random not existing command",
			input: funcInput{
				args: []string{"random-not-existing-command"},
			},
			error: true,
		},
	}
	for i, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExecuteCommand(tt.input.args, tt.input.networkArgs)
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
