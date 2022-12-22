package utils

import (
	"fmt"
	"os/exec"
	"regexp"
)

// AppendKeyWithValueIfNotEmpty appends the given key and value to the args if the value is not empty
func AppendKeyWithValueIfNotEmpty(args []string, arg, value string) []string {
	if value != "" {
		return append(args, arg, value)
	}
	return args
}

// ExecuteCommand executes a command with the given args and returns the raw stdout and error
func ExecuteCommand(args, networkArgs []string) (cmdOutput []byte, err error) {
	if len(args) < 1 {
		err = fmt.Errorf("executeCommand: args must be non-empty")
		return
	}
	args = append(args, networkArgs...)

	cmd := exec.Command(args[0], args[1:]...)

	cmdOutput, err = cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("response error: %w\nargs: %s\nstdout: %s", err, args, cmdOutput)
	}
	return
}

// RegexFunctionFactory returns a function that can be used to extract a string from the stdout of a command
func RegexFunctionFactory(regexString, objectName string) func(rawStdout []byte) (string, error) {
	return func(rawStdout []byte) (string, error) {
		regex := regexp.MustCompile(regexString)
		if !regex.Match(rawStdout) {
			return "", fmt.Errorf("could not find %s in stdout: %s", objectName, rawStdout)
		}
		return string(regex.FindSubmatch(rawStdout)[1]), nil
	}
}
