//
// Contains helper functions for dealing with configuration files
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
)

// GetHomeDir gets current user directory
func GetHomeDir() string {
	usr, err := user.Current()
	if err != nil {
		fmt.Printf("\n\n[!] Error : %v\n", err)
		os.Exit(1)
	}

	return usr.HomeDir
}

// Exists returns whether the given file or directory exists or not
func Exists(path string) bool {
	_, err := os.Stat(path)

	if err == nil {
		return true
	}

	if os.IsNotExist(err) {
		return false
	}

	return true
}

// CreateDirIfNotExist creates config directory if it does not exists
func CreateDirIfNotExist(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			fmt.Printf("\n\n[!] Error : %v\n", err)
			os.Exit(1)
		}
	}
}

// ReadConfigFile Reads a config file from disk and returns Configuration structure
// If not exists, create one and then return
func ReadConfigFile() (configuration *Config, err error) {
	var config Config

	// Get current path
	home := GetHomeDir()

	path := home + "/.config/subfinder/config.json"

	if Exists(path) {
		raw, err := ioutil.ReadFile(path)
		if err != nil {
			return &config, err
		}

		err = json.Unmarshal(raw, &config)
		if err != nil {
			return &config, err
		}

		return &config, nil
	}
	CreateDirIfNotExist(home + "/.config/subfinder/")
	configJSON, _ := json.MarshalIndent(config, "", "	")
	err = ioutil.WriteFile(path, configJSON, 0644)
	if err != nil {
		fmt.Printf("\n\n[!] Error : %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[NOTE] Edit %s with your options !", path)
	return &config, nil
}
