//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package dnstable is a Golang driver for dnstable.com
package dnstable

import (
	"fmt"
	"io/ioutil"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Make a http request to Netcraft
	resp, err := helper.GetHTTPResponse("https://dnstable.com/domain/"+domain, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ndnstable: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ndnstable: %v\n", err)
		}
		return subdomains
	}

	src := string(body)

	match := helper.ExtractSubdomains(src, domain)

	for _, subdomain := range match {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sDNSTABLE%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[DNSTABLE] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}
