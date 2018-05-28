//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A Golang based client for Threatcrowd API
package threatcrowd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// Struct containing json data we actually need
type threatcrowd_object struct {
	Subdomains []string `json:"subdomains"`
}

// array of all results returned
var threatcrowd_data threatcrowd_object

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to Threatcrowd
	resp, err := helper.GetHTTPResponse("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+domain, state.Timeout)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	// Get the response body
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	// Decode the json format
	err = json.Unmarshal([]byte(resp_body), &threatcrowd_data)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	// Append each subdomain found to subdomains array
	for _, subdomain := range threatcrowd_data.Subdomains {

		// Fix Wildcard subdomains containg asterisk before them
		if strings.Contains(subdomain, "*.") {
			subdomain = strings.Split(subdomain, "*.")[1]
		}

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sTHREATCROWD%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[THREATCROWD] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
