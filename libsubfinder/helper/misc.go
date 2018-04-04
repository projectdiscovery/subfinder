// 
// misc.go : contains misc helper function
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"io/ioutil"
	"encoding/json"
)

// Current result structure
type Result struct {
    Subdomains []string     // Subdomains found
    Error      error        // Any error that has occured
}

//
// ReadConfigFile : Reads a config file from disk
// 
// @return config : configuration structure
// @return err : if no error nil, else error
//
func ReadConfigFile() (configuration *Config, err error) {

	var config Config

	// Read the file
	raw, err := ioutil.ReadFile("./config.json")
    if err != nil {
        return &config, err
    }

    err = json.Unmarshal(raw, &config)
    if (err != nil) {
    	return &config, err
    }

    return &config, nil
}

// 
// Returns unique items in a slice
// Adapted from http://www.golangprograms.com/remove-duplicate-values-from-slice.html
//
func Unique(strSlice []string) []string {
    keys := make(map[string]bool)
    list := []string{} 
    for _, entry := range strSlice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }    
    return list
}
