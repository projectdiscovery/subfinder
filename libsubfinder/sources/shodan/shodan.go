//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Shodan.io
package shodan

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains
	shodanAPIKey := state.ConfigState.ShodanAPIKey
	maxPages, _ := strconv.Atoi(state.CurrentSettings.ShodanPages)
	for currentPage := 0; currentPage <= maxPages; currentPage++ {
		resp, err := helper.GetHTTPResponse("https://api.shodan.io/shodan/host/search?query=hostname:"+domain+"&page="+strconv.Itoa(currentPage)+"&key="+shodanAPIKey, state.Timeout)
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
		src := string(body)

		re := regexp.MustCompile(`([a-z0-9]+\.)+` + domain)
		match := re.FindAllString(src, -1)

		for _, subdomain := range match {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sShodan%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Shodan] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
		}
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
