//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A Golang based client for Parsing Subdomains from Waybackarchive
package waybackarchive

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to Threatcrowd
	resp, err := helper.GetHTTPResponse("http://web.archive.org/cdx/search/cdx?url=*."+domain+"/*&output=json&fl=original&collapse=urlkey", state.Timeout)
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

	var urls [][]string

	// Decode the json format
	err = json.Unmarshal([]byte(resp_body), &urls)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	var initialSubs []string

	// Append each subdomain found to subdomains array
	for _, url := range urls {

		// leave first string since it's always original
		if url[0] == "original" {
			continue
		}

		first := strings.Split(strings.Split(url[0], "//")[1], "/")[0]

		subdomain := first
		if strings.Contains(first, ":") {
			subdomain = strings.Split(first, ":")[0]
		}

		initialSubs = append(initialSubs, subdomain)
	}

	validSubdomains := helper.Unique(initialSubs)

	for _, subdomain := range validSubdomains {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sWAYBACKARCHIVE%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[WAYBACKARCHIVE] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
