//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package ask is a golang client for Ask Subdomain Discovery
package ask

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"sort"
	"strconv"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) (i interface{}) {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	minIterations, _ := strconv.Atoi(state.CurrentSettings.AskPages)
	maxIterations := 760
	searchQuery := ""
	currentPage := 0
	for currentIteration := 0; currentIteration <= maxIterations; currentIteration++ {
		newSearchQuery := "site:" + domain
		if len(subdomains) > 0 {
			newSearchQuery += " -www." + domain
		}
		newSearchQuery = url.QueryEscape(newSearchQuery)
		if searchQuery != newSearchQuery {
			currentPage = 0
			searchQuery = newSearchQuery
		}

		resp, err := helper.GetHTTPResponse("http://www.ask.com/web?q="+searchQuery+"&page="+strconv.Itoa(currentPage)+"&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination", state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nask: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nask: %v\n", err)
			}
			return subdomains
		}
		src := string(body)

		match := helper.ExtractSubdomains(src, domain)

		newSubdomainsFound := 0
		for _, subdomain := range match {
			if !sort.StringsAreSorted(subdomains) {
				sort.Strings(subdomains)
			}

			insertIndex := sort.SearchStrings(subdomains, subdomain)
			if insertIndex < len(subdomains) && subdomains[insertIndex] == subdomain {
				continue
			}

			if state.Verbose {
				if state.Color {
					fmt.Printf("\n[%sAsk%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Ask] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
			newSubdomainsFound++
		}
		// If no new subdomains are found exits after minIterations
		if newSubdomainsFound == 0 && currentIteration > minIterations {
			break
		}
		currentPage++
	}

	return subdomains
}
