// 
// threatcrowd.go : A Golang based client for Threatcrowd API
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package threatcrowd

import (
	"io/ioutil"
	"encoding/json"
	"strings"
	"fmt"

	"subfinder/libsubfinder/helper"
)

// Struct containing json data we actually need
type threatcrowd_object struct {
	Subdomains	[]string `json:"subdomains"`
}

// array of all results returned
var threatcrowd_data threatcrowd_object

// 
// Query : Queries awesome ThreatCrowd service for subdomains
// @param state : current application state, holds all information found
// 
// @return subdomain : String array containing subdomains found
// @return err : nil if successfull and error if failed
//
func Query(state *helper.State) (subdomains []string, err error) {

	// Make a http request to Threatcrowd
	resp, err := helper.GetHTTPResponse("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="+state.Domain, 3000)
	if err != nil {
		return subdomains, err
	}

	// Get the response body
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return subdomains, err
	}

	// Decode the json format
	err = json.Unmarshal([]byte(resp_body), &threatcrowd_data)
	if err != nil {
		return subdomains, err
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

	return subdomains, nil
}
