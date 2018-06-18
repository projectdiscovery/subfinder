//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Exalead Subdomain Discovery
package exalead

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains

	url := "http://www.exalead.com/search/web/results/?q=site:" + domain + "+-www?elements_per_page=50"
	resp, err := helper.GetHTTPResponse(url, state.Timeout)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	reSub := regexp.MustCompile(`%.{2}`)
	src := reSub.ReplaceAllLiteralString(string(body), " ")

	re := helper.SubdomainRegex(domain)
	match := re.FindAllString(src, -1)

	for _, subdomain := range match {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sExalead%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[Exalead] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
