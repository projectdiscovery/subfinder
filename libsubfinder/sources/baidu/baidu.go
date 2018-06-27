//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package baidu is a golang client for Baidu Subdomain Discovery
package baidu

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	minIterations, _ := strconv.Atoi(state.CurrentSettings.BaiduPages)
	maxIterations := 760
	searchQuery := ""
	currentPage := 0
	for currentIteration := 0; currentIteration <= maxIterations; currentIteration++ {
		newSearchQuery := "site:" + domain
		if len(subdomains) > 0 {
			newSearchQuery += " -site:www." + domain
		}
		newSearchQuery = url.QueryEscape(newSearchQuery)
		if searchQuery != newSearchQuery {
			currentPage = 0
			searchQuery = newSearchQuery
		}

		resp, err := helper.GetHTTPResponse("https://www.baidu.com/s?rn=100&pn="+strconv.Itoa(currentPage)+"&wd="+searchQuery+"&oq="+searchQuery, state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nbaidu: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nbaidu: %v\n", err)
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
					fmt.Printf("\n[%sBaidu%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Baidu] %s", subdomain)
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
		time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)
	}

	return subdomains
}
