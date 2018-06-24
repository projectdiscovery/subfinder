//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A Golang based client for Certspotter Parsing
package certspotter

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// Structure of a single dictionary of output by crt.sh
type certspotter_object struct {
	Dns_names []string `json:"dns_names"`
}

// array of all results returned
var certspotter_data []certspotter_object

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

	// Get the response body
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertspotter: %v\n", err)
		}
		return subdomains
	}

	// Decode the json format
	err = json.Unmarshal([]byte(resp_body), &certspotter_data)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertspotter: %v\n", err)
		}
		return subdomains
	}

	// Append each subdomain found to subdomains array
	for _, block := range certspotter_data {
		for _, dns_name := range block.Dns_names {

			// Fix Wildcard subdomains containg asterisk before them
			if strings.Contains(dns_name, "*.") {
				dns_name = strings.Split(dns_name, "*.")[1]
			}

			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sCERTSPOTTER%s] %s", helper.Red, helper.Reset, dns_name)
				} else {
					fmt.Printf("\n[CERTSPOTTER] %s", dns_name)
				}
			}

			subdomains = append(subdomains, dns_name)
		}
	}

	return subdomains
}
