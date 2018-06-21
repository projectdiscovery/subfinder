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
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	shodanAPIKey := state.ConfigState.ShodanAPIKey
	maxPages, _ := strconv.Atoi(state.CurrentSettings.ShodanPages)
	for currentPage := 0; currentPage <= maxPages; currentPage++ {
		resp, err := helper.GetHTTPResponse("https://api.shodan.io/shodan/host/search?query=hostname:"+domain+"&page="+strconv.Itoa(currentPage)+"&key="+shodanAPIKey, state.Timeout)
		if err != nil {
			fmt.Printf("\nshodan: %v\n", err)
			return subdomains
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("\nshodan: %v\n", err)
			return subdomains
		}

		reSub := regexp.MustCompile(`"`)
		src := reSub.ReplaceAllLiteralString(string(body), " ")

		match := helper.ExtractSubdomains(src, domain)

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

	return subdomains
}
