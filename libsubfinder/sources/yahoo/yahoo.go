//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Yahoo Subdomain Discovery
package yahoo

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
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
	maxPages, _ := strconv.Atoi(state.CurrentSettings.YahooPages)
	for currentPage := 0; currentPage <= maxPages; currentPage++ {
		url := "https://search.yahoo.com/search?p=site:" + domain + "&b=" + strconv.Itoa(currentPage*10) + "&pz=10&bct=0&xargs=0"
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
					fmt.Printf("\n[%sYahoo%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Yahoo] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
		}
		time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
