//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package ptrarchive is a PTRArchive subdomain parser in golang
package ptrarchive

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Make a http request to CertDB
	resp, err := helper.GetHTTPResponse("http://ptrarchive.com/tools/search3.htm?label="+domain+"&date=ALL", state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nptrarchive: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nptrarchive: %v\n", err)
		}
		return subdomains
	}

	src := string(body)

	// Parse Subdomains found
	Regex, _ := regexp.Compile("] (.*) \\[")
	match := Regex.FindAllStringSubmatch(src, -1)

	// String to hold initial subdomains
	var initialSubs []string

	for _, data := range match {
		initialSubs = append(initialSubs, data[1])
	}

	validSubdomains := helper.Validate(domain, initialSubs)

	for _, subdomain := range validSubdomains {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sPTRARCHIVE%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[PTRARCHIVE] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}
