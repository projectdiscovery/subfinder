//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package ask ... A golang client for Ask Subdomain Discovery
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
	current_page := 0
	for current_iteration := 0; current_iteration <= maxIterations; current_iteration++ {
		new_searchQuery := "site:" + domain
		if len(subdomains) > 0 {
			new_searchQuery += " -www." + domain
		}
		new_searchQuery = url.QueryEscape(new_searchQuery)
		if searchQuery != new_searchQuery {
			current_page = 0
			searchQuery = new_searchQuery
		}

		resp, err := helper.GetHTTPResponse("http://www.ask.com/web?q="+searchQuery+"&page="+strconv.Itoa(current_page)+"&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination", state.Timeout)
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

		new_subdomains_found := 0
		for _, subdomain := range match {
			if sort.StringsAreSorted(subdomains) == false {
				sort.Strings(subdomains)
			}

			insert_index := sort.SearchStrings(subdomains, subdomain)
			if insert_index < len(subdomains) && subdomains[insert_index] == subdomain {
				continue
			}

			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sAsk%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Ask] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
			new_subdomains_found++
		}
		// If no new subdomains are found exits after minIterations
		if new_subdomains_found == 0 && current_iteration > minIterations {
			break
		}
		current_page++
	}

	return subdomains
}
