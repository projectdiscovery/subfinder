//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package passivetotal is a golang client for Passive total Subdomain Discovery
package passivetotal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

type passivetotalObject struct {
	Subdomains []string `json:"subdomains"`
}

var passivetotalData passivetotalObject

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Get credentials for performing HTTP Basic Auth
	username := state.ConfigState.PassivetotalUsername
	key := state.ConfigState.PassivetotalKey

	if username == "" || key == "" {
		return subdomains
	}

	// Create JSON Get body
	var request = []byte(`{"query":"` + domain + `"}`)

	client := &http.Client{}
	req, err := http.NewRequest("GET", "https://api.passivetotal.org/v2/enrichment/subdomains", bytes.NewBuffer(request))
	if err != nil {
		if !state.Silent {
			fmt.Printf("\npassivetotal: %v\n", err)
		}
		return subdomains
	}

	req.SetBasicAuth(username, key)

	// Set content type as application/json
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\npassivetotal: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\npassivetotal: %v\n", err)
		}
		return subdomains
	}

	// Decode the json format
	err = json.Unmarshal([]byte(body), &passivetotalData)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\npassivetotal: %v\n", err)
		}
		return subdomains
	}

	// Append each subdomain found to subdomains array
	for _, subdomain := range passivetotalData.Subdomains {
		finalSubdomain := subdomain + "." + domain

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sPASSIVETOTAL%s] %s", helper.Red, helper.Reset, finalSubdomain)
			} else {
				fmt.Printf("\n[PASSIVETOTAL] %s", finalSubdomain)
			}
		}

		subdomains = append(subdomains, finalSubdomain)
	}

	return subdomains
}
