//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package hackertarget is a golang based Hackertarget subdomains search client
package hackertarget

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	var result helper.Result
	result.Subdomains = subdomains

	resp, err := helper.GetHTTPResponse("https://api.hackertarget.com/hostsearch/?q="+domain, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nhackertarget: %v\n", err)
		}
		return subdomains
	}
	defer resp.Body.Close()

	// Get the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nhackertarget: %v\n", err)
		}
		return subdomains
	}

	scanner := bufio.NewScanner(strings.NewReader(string(respBody)))
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

	return subdomains
}
