//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package exalead is a golang client for Exalead Subdomain Discovery
package exalead

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

	url := "http://www.exalead.com/search/web/results/?q=site:" + domain + "+-www?elements_per_page=50"
	resp, err := helper.GetHTTPResponse(url, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nexalead: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nexalead: %v\n", err)
		}
		return subdomains
	}

	reSub := regexp.MustCompile(`%.{2}`)
	src := reSub.ReplaceAllLiteralString(string(body), " ")

	match := helper.ExtractSubdomains(src, domain)

	for _, subdomain := range match {
		if helper.SubdomainExists(subdomain, subdomains) == false {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sExalead%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Exalead] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)

		}
	}

	return subdomains
}
