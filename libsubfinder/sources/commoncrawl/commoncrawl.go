//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package commoncrawl is a Golang based client for Parsing Subdomains from Commoncrawl
package commoncrawl

import (
	"fmt"
	"io/ioutil"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

type commoncrawlObject struct {
	NameValue string `json:"url"`
}

// array of all results returned
var commoncrawlData []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Make a http request to Threatcrowd
	resp, err := helper.GetHTTPResponse("http://index.commoncrawl.org/CC-MAIN-2018-17-index?url=*."+domain+"&output=json", state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncommoncrawl: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncommoncrawl: %v\n", err)
		}
		return subdomains
	}

	commoncrawlData := helper.ExtractSubdomains(string(respBody), domain)

	for _, subdomain := range commoncrawlData {
		if helper.SubdomainExists(subdomain, subdomains) == false {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sCommoncrawl%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Commoncrawl] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains

}
