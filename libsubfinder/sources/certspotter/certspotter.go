//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package certspotter is a Golang based client for Certspotter Parsing
package certspotter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// Structure of a single dictionary of output by crt.sh
type certspotterObject struct {
	DNSNames []string `json:"dns_names"`
}

// array of all results returned
var certspotterData []certspotterObject

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Make a http request to Certspotter
	resp, err := helper.GetHTTPResponse("https://certspotter.com/api/v0/certs?domain="+domain, state.Timeout)
	if err != nil {
		if !state.Silent {
			// Set values and return
			fmt.Printf("\ncertspotter: %v\n", err)
		}
		return subdomains
	}

	// Decode as json format
	err = json.NewDecoder(resp.Body).Decode(&certspotterData)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertspotter: %v\n", err)
		}
		return subdomains
	}

	// Append each subdomain found to subdomains array
	for _, block := range certspotterData {
		for _, dnsName := range block.DNSNames {

			// Fix Wildcard subdomains containing asterisk before them
			if strings.Contains(dnsName, "*.") {
				dnsName = strings.Split(dnsName, "*.")[1]
			}

			if state.Verbose {
				if state.Color {
					fmt.Printf("\n[%sCERTSPOTTER%s] %s", helper.Red, helper.Reset, dnsName)
				} else {
					fmt.Printf("\n[CERTSPOTTER] %s", dnsName)
				}
			}

			subdomains = append(subdomains, dnsName)
		}
	}

	return subdomains
}
