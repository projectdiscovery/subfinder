// 
// certspotter.go : A Golang based client for Certspotter Parsing
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package certspotter

import (
	"io/ioutil"
	"encoding/json"
	"strings"
	"fmt"

	"subfinder/libsubfinder/helper"
)

// Structure of a single dictionary of output by crt.sh
type certspotter_object struct {
	Dns_names	[]string `json:"dns_names"`
}

// array of all results returned
var certspotter_data []certspotter_object

// 
// Query : Queries awesome Certspotter service for subdomains
// @param state : current application state, holds all information found
// 
// @return subdomain : String array containing subdomains found
// @return err : nil if successfull and error if failed
//
func Query(state *helper.State) (subdomains []string, err error) {

	// Make a http request to Certspotter
	resp, err := helper.GetHTTPResponse("https://certspotter.com/api/v0/certs?domain="+state.Domain, 3000)
	if err != nil {
		return subdomains, err
	}

	// Get the response body
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return subdomains, err
	}

	// Decode the json format
	err = json.Unmarshal([]byte(resp_body), &certspotter_data)
	if err != nil {
		return subdomains, err
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
					fmt.Printf("\n[\033[31;1;4mCERTSPOTTER\033[0m] %s", dns_name)
				} else {
					fmt.Printf("\n[CERTSPOTTER] %s", dns_name)
				}
			}

			subdomains = append(subdomains, dns_name)
		}	
	}

	return subdomains, nil
}
