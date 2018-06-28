//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package archiveis is a Archiveis Scraping Engine in Golang
package archiveis

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// Contains all subdomains found
var globalSubdomains []string

func enumerate(state *helper.State, baseURL string, domain string) (err error) {
	resp, err := helper.GetHTTPResponse(baseURL, state.Timeout)
	if err != nil {
		return err
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	src := string(body)

	match := helper.ExtractSubdomains(src, domain)

	for _, subdomain := range match {
		finishedSub := subdomain

		if !helper.SubdomainExists(finishedSub, globalSubdomains) {
			if state.Verbose {
				if state.Color {
					fmt.Printf("\n[%sARCHIVE.IS%s] %s", helper.Red, helper.Reset, finishedSub)
				} else {
					fmt.Printf("\n[ARCHIVE.IS] %s", finishedSub)
				}
			}

			globalSubdomains = append(globalSubdomains, finishedSub)
		}
	}

	reNext := regexp.MustCompile("<a id=\"next\" style=\".*\" href=\"(.*)\">&rarr;</a>")
	match1 := reNext.FindStringSubmatch(src)

	if len(match1) > 0 {
		enumerate(state, match1[1], domain)
	}

	return nil
}

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) (i interface{}) {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Query using first page. Everything from there would be recursive
	err := enumerate(state, "http://archive.is/*."+domain, domain)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\narchiveis: %v\n", err)
		}
		return globalSubdomains
	}

	return globalSubdomains
}
