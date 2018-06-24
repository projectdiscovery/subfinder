//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package yahoo is a golang client for Yahoo Subdomain Discovery
package yahoo

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
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

	maxPages, _ := strconv.Atoi(state.CurrentSettings.YahooPages)
	for currentPage := 0; currentPage <= maxPages; currentPage++ {
		url := "https://search.yahoo.com/search?p=site:" + domain + "&b=" + strconv.Itoa(currentPage*10) + "&pz=10&bct=0&xargs=0"
		resp, err := helper.GetHTTPResponse(url, state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nyahoo: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nyahoo: %v\n", err)
			}
			return subdomains
		}

		reSub := regexp.MustCompile(`%.{2}`)
		src := reSub.ReplaceAllLiteralString(string(body), " ")

		match := helper.ExtractSubdomains(src, domain)

		for _, subdomain := range match {
			if helper.SubdomainExists(subdomain, subdomains) == false {
				if state.Verbose == true {
					if state.Color == true {
						fmt.Printf("\n[%sYahoo%s] %s", helper.Red, helper.Reset, subdomain)
					} else {
						fmt.Printf("\n[Yahoo] %s", subdomain)
					}
				}

				subdomains = append(subdomains, subdomain)
			}
		}
		time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)
	}

	return subdomains
}
