//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package dogpile is a golang client for Dogpile Subdomain Discovery
package dogpile

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
	maxPages, _ := strconv.Atoi(state.CurrentSettings.DogpilePages)
	for currentPage := 0; currentPage <= maxPages; currentPage++ {
		url := "http://www.dogpile.com/search/web?q=" + domain + "&qsi=" + strconv.Itoa(currentPage*15+1)

		resp, err := helper.GetHTTPResponse(url, state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\ndogpile: %v\n", err)
			}
			return subdomains
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\ndogpile: %v\n", err)
			}
			return subdomains
		}

		reSub := regexp.MustCompile(`%.{4}`)
		src := reSub.ReplaceAllLiteralString(string(body), " ")

		match := helper.ExtractSubdomains(src, domain)

		for _, subdomain := range match {
			if helper.SubdomainExists(subdomain, subdomains) == false {
				if state.Verbose == true {
					if state.Color == true {
						fmt.Printf("\n[%sDogpile%s] %s", helper.Red, helper.Reset, subdomain)
					} else {
						fmt.Printf("\n[Dogpile] %s", subdomain)
					}
				}

				subdomains = append(subdomains, subdomain)
			}
		}
		time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)
	}

	return subdomains
}
