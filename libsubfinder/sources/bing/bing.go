//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package bing is a golang client for Bing Subdomain Discovery
package bing

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"sort"
	"strconv"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	minIterations, _ := strconv.Atoi(state.CurrentSettings.BingPages)
	maxIterations := 760
	searchQuery := ""
	currentPage := 0
	for currentIteration := 0; currentIteration <= maxIterations; currentIteration++ {
		newSearchQuery := "domain:" + domain
		if len(subdomains) > 0 {
			newSearchQuery += " -www." + domain
		}
		newSearchQuery = url.QueryEscape(newSearchQuery)
		if searchQuery != newSearchQuery {
			currentPage = 0
			searchQuery = newSearchQuery
		}

		resp, err := helper.GetHTTPResponse("https://www.bing.com/search?q="+searchQuery+"&go=Submit&first="+strconv.Itoa(currentPage), state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nbing: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("\nbing: %v\n", err)
			return subdomains
		}

		// suppress all %xx sequences with a space
		reSub := regexp.MustCompile(`%.{2}`)
		src := reSub.ReplaceAllLiteralString(string(body), " ")

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
					fmt.Printf("\n[%sBing%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Bing] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
			newSubdomainsFound++
		}
		// If no new subdomains are found exits after min_iterations
		if newSubdomainsFound == 0 && currentIteration > minIterations {
			break
		}
		currentPage++
	}

	return subdomains
}
