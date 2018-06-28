//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package virustotal is a golang Client for Subdomain Enumeration
package virustotal

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

type virustotalapiObject struct {
	Subdomains []string `json:"subdomains"`
}

var virustotalapiData virustotalapiObject

// Local function to query virustotal API
// Requires an API key
func queryVirustotalAPI(domain string, state *helper.State) (subdomains []string, err error) {

	// Make a search for a domain name and get HTTP Response
	resp, err := helper.GetHTTPResponse("https://www.virustotal.com/vtapi/v2/domain/report?apikey="+state.ConfigState.VirustotalAPIKey+"&domain="+domain, state.Timeout)
	if err != nil {
		return subdomains, err
	}

	// Get the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return subdomains, err
	}

	// Decode the json format
	err = json.Unmarshal([]byte(respBody), &virustotalapiData)
	if err != nil {
		return subdomains, err
	}

	// Append each subdomain found to subdomains array
	for _, subdomain := range virustotalapiData.Subdomains {

		// Fix Wildcard subdomains containing asterisk before them
		if strings.Contains(subdomain, "*.") {
			subdomain = strings.Split(subdomain, "*.")[1]
		}

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sVIRUSTOTAL%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[VIRUSTOTAL] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	var subdomains []string

	if state.ConfigState.VirustotalAPIKey == "" {
		return subdomains
	}

	// Get subdomains via API
	subdomains, err := queryVirustotalAPI(domain, state)

	if err != nil {
		if !state.Silent {
			fmt.Printf("\nvirustotal: %v\n", err)
		}
		return subdomains
	}

	return subdomains
}
