//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package findsubdomains is a Golang driver for findsubdomains.com
package findsubdomains

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Make a http request to Netcraft
	resp, err := helper.GetHTTPResponse("https://findsubdomains.com/subdomains-of/"+domain, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nfindsubdomains: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nfindsubdomains: %v\n", err)
		}
		return subdomains
	}

	src := string(body)

	re := regexp.MustCompile("<a class=\"aggregated-link\" rel=\"nofollow\" href=\"(.*)\" target=\"_blank\">")
	match := re.FindAllStringSubmatch(src, -1)

	for _, subdomain := range match {
		// Dirty Logic
		finishedSub := strings.Split(subdomain[1], "//")[1]

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sFINDSUBDOMAINS%s] %s", helper.Red, helper.Reset, finishedSub)
			} else {
				fmt.Printf("\n[FINDSUBDOMAINS] %s", finishedSub)
			}
		}

		subdomains = append(subdomains, finishedSub)
	}

	return subdomains
}
