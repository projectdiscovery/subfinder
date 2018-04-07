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
    "crypto/rand"
    "io"
    "strings"
	"encoding/json"
    "fmt"
)

// Current result structure
type Result struct {
    Subdomains []string     // Subdomains found
    Error      error        // Any error that has occured
}

// Current Bruteforce structure
type BruteforceResult struct {
    Entity  string          // Current Subdomain we found
    Error   error           // Error
}


// 
// NewUUID generates a random UUID according to RFC 4122
// Taken from : https://play.golang.org/p/4FkNSiUDMg
// 
// Used for bruteforcing and detection of Wildcard Subdomains :-)
func NewUUID() (string, error) {
    uuid := make([]byte, 16)
    n, err := io.ReadFull(rand.Reader, uuid)
    if n != len(uuid) || err != nil {
        return "", err
    }
    // variant bits; see section 4.1.1
    uuid[8] = uuid[8]&^0xc0 | 0x80
    // version 4 (pseudo-random); see section 4.1.3
    uuid[6] = uuid[6]&^0xf0 | 0x40
    return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
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

//
// Returns unique valid subdomains found 
//
func Validate(state *State, strslice []string) (subdomains []string) {
    for _, entry := range strslice {
        if strings.Contains(entry, state.Domain) {
            subdomains = append(subdomains, entry)
        }
    }

    return subdomains
}