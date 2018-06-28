//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package shodan is a golang client for Shodan.io
package shodan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

type ShodanResult struct {
	Matches []shodanObject `json:"matches"`
	Result  int            `json:"result"`
	Error   string         `json:"error"`
}

// Structure of a single dictionary of output by crt.sh
type shodanObject struct {
	Hostnames []string `json:"hostnames"`
}

var shodanResult ShodanResult

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	shodanAPIKey := state.ConfigState.ShodanAPIKey

	if shodanAPIKey == "" {
		return subdomains
	}

	maxPages, _ := strconv.Atoi(state.CurrentSettings.ShodanPages)
	for currentPage := 0; currentPage <= maxPages; currentPage++ {
		resp, err := helper.GetHTTPResponse("https://api.shodan.io/shodan/host/search?query=hostname:"+domain+"&page="+strconv.Itoa(currentPage)+"&key="+shodanAPIKey, state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nshodan: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nshodan: %v\n", err)
			}
			return subdomains
		}

		// Decode the json format
		err = json.Unmarshal([]byte(respBody), &shodanResult)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nshodan: %v\n", err)
			}
			return subdomains
		}

		if shodanResult.Error != "" {
			return subdomains
		}

		// Append each subdomain found to subdomains array
		for _, block := range shodanResult.Matches {
			for _, hostname := range block.Hostnames {

				// Fix Wildcard subdomains containg asterisk before them
				if strings.Contains(hostname, "*.") {
					hostname = strings.Split(hostname, "*.")[1]
				}

				if state.Verbose {
					if state.Color {
						fmt.Printf("\n[%sSHODAN%s] %s", helper.Red, helper.Reset, hostname)
					} else {
						fmt.Printf("\n[SHODAN] %s", hostname)
					}
				}

				subdomains = append(subdomains, hostname)
			}
		}
	}

	return subdomains
}
