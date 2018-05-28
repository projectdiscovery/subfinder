//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang based Hackertarget subdomains search client
package hackertarget

import (
	"bufio"
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

	resp, err := helper.GetHTTPResponse("https://api.hackertarget.com/hostsearch/?q="+domain, state.Timeout)
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

	scanner := bufio.NewScanner(strings.NewReader(string(resp_body)))
	for scanner.Scan() {
		subdomain := strings.Split(scanner.Text(), ",")[0]
		subdomains = append(subdomains, subdomain)

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sHACKERTARGET%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[HACKERTARGET] %s", subdomain)
			}
		}
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
