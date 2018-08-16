//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package waybackarchive is a Golang based client for Parsing Subdomains from Waybackarchive
package waybackarchive

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	pagesResp, err := helper.GetHTTPResponse("http://web.archive.org/cdx/search/cdx?url=*."+domain+"&showNumPages=true", state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nwaybackarchive: %v\n", err)
		}
		return subdomains
	}

	b, err := ioutil.ReadAll(pagesResp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nwaybackarchive: %v\n", err)
		}
		return subdomains
	}

	numPages, err := strconv.Atoi(strings.Split(string(b), "\n")[0])
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nwaybackarchive: %v\n", err)
		}
		return subdomains
	}

	for i := 0; i <= numPages; i++ {
		resp, err := helper.GetHTTPResponse("http://web.archive.org/cdx/search/cdx?url=*."+domain+"/*&output=json&fl=original&collapse=urlkey&page="+string(i), state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nwaybackarchive: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nwaybackarchive: %v\n", err)
			}
			return subdomains
		}

		initialSubs := helper.ExtractSubdomains(string(respBody), domain)
		validSubdomains := helper.Unique(initialSubs)

		for _, subdomain := range validSubdomains {
			if helper.SubdomainExists(subdomain, subdomains) == false {
				if state.Verbose == true {
					if state.Color == true {
						fmt.Printf("\n[%sWAYBACKARCHIVE%s] %s", helper.Red, helper.Reset, subdomain)
					} else {
						fmt.Printf("\n[WAYBACKARCHIVE] %s", subdomain)
					}
				}

				subdomains = append(subdomains, subdomain)
			}
		}
	}

	return subdomains
}
