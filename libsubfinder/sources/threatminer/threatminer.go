//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package threatminer is a Threatminer subdomain parser in golang
package threatminer

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
	resp, err := helper.GetHTTPResponse("https://www.threatminer.org/getData.php?e=subdomains_container&q="+domain+"&t=0&rt=10&p=1", state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nthreatminer: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nthreatminer: %v\n", err)
		}
		return subdomains
	}

	src := string(body)

	// Parse Subdomains found
	Regex, _ := regexp.Compile("\"domain\\.php\\?q=([a-zA-Z0-9\\*_.-]+\\." + domain + ")")
	match := Regex.FindAllStringSubmatch(src, -1)

	for _, m := range match {

		// First Capturing group
		subdomain := m[1]

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sTHREATMINER%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[THREATMINER] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}
