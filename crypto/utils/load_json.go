package utils

import (
	"encoding/json"
	"os"
)

type HashFeltTestCaseArray struct {
	Name     string  `json:"Name"`
	Array    []int64 `json:"Array"`
	Expected string  `json:"Expected"`
}

func ImportJsonArray(path string) []HashFeltTestCaseArray {

	var data_out []HashFeltTestCaseArray
	// var data_out []byte

	json_file, _ := os.ReadFile(path)
	err := json.Unmarshal(json_file, &data_out)
	if err != nil {
		panic(err)
	}
	return data_out
}

type HashCanonicalVoteNoTimeArray struct {
	Name                 string `json:"Name"`
	PSHTotal             uint32 `json:"PSHTotal"`
	PSHHash              int64  `json:"PSHHash"`
	CanonicalBlockIDHash int64  `json:"CanonicalBlockIDHash"`
	Time                 int64  `json:"Time"`
	Type                 int32  `json:"Type"`
	Height               int64  `json:"Height"`
	Round                int64  `json:"Round"`
	ChainID              string `json:"ChainID"`
	ChainIDFelt          int64  `json:"ChainIDFelt"`
	Expected             string `json:"Expected"`
}

func LoadJsonHCVNTA(path string) HashCanonicalVoteNoTimeArray {

	var data_out HashCanonicalVoteNoTimeArray

	json_file, _ := os.ReadFile(path)
	err := json.Unmarshal(json_file, &data_out)
	if err != nil {
		panic(err)
	}
	return data_out
}

type TimeArray struct {
	Name     string `json:"Name"`
	Time     int64  `json:"Time"`
	Expected string `json:"Expected"`
}

func LoadJsonHashTime(path string) TimeArray {

	var data_out TimeArray

	json_file, _ := os.ReadFile(path)
	err := json.Unmarshal(json_file, &data_out)
	if err != nil {
		panic(err)
	}
	return data_out
}

type CPSetHeaderArray struct {
	Name     string `json:"Name"`
	Total    uint32 `json:"Total"`
	Hash     int64  `json:"Hash"`
	Expected string `json:"Expected"`
}

func LoadJsonCPSetHeader(path string) CPSetHeaderArray {

	var data_out CPSetHeaderArray

	json_file, _ := os.ReadFile(path)
	err := json.Unmarshal(json_file, &data_out)
	if err != nil {
		panic(err)
	}
	return data_out
}
