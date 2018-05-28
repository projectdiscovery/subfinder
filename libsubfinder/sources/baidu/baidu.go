//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Baidu Subdomain Discovery
package baidu

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains
	min_iterations, _ := strconv.Atoi(state.CurrentSettings.BaiduPages)
	max_iterations := 760
	search_query := ""
	current_page := 0
	for current_iteration := 0; current_iteration <= max_iterations; current_iteration++ {
		new_search_query := "site:" + domain
		if len(subdomains) > 0 {
			new_search_query += " -site:www." + domain
		}
		new_search_query = url.QueryEscape(new_search_query)
		if search_query != new_search_query {
			current_page = 0
			search_query = new_search_query
		}

		resp, err := helper.GetHTTPResponse("https://www.baidu.com/s?rn=100&pn="+strconv.Itoa(current_page)+"&wd="+search_query+"&oq="+search_query, state.Timeout)
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
					fmt.Printf("\n[%sBaidu%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Baidu] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
			new_subdomains_found++
		}
		// If no new subdomains are found exits after min_iterations
		if new_subdomains_found == 0 && current_iteration > min_iterations {
			break
		}
		current_page++
		time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
