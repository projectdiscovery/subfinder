//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Archiveis Scraping Engine in Golang
package archiveis

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// Contains all subdomains found
var globalSubdomains []string

// Local function to recursively enumerate subdomains until no subdomains
// are left
func enumerate(state *helper.State, baseUrl string, domain string) (err error) {

	// Make a http request to Netcraft
	resp, err := helper.GetHTTPResponse(baseUrl, state.Timeout)
	if err != nil {
		return err
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	src := string(body)

	re := regexp.MustCompile(`([a-z0-9]+\.)+` + domain)
	match := re.FindAllStringSubmatch(src, -1)

	for _, subdomain := range match {
		finishedSub := subdomain[0]

		if helper.SubdomainExists(finishedSub, globalSubdomains) == false {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sARCHIVE.IS%s] %s", helper.Red, helper.Reset, finishedSub)
				} else {
					fmt.Printf("\n[ARCHIVE.IS] %s", finishedSub)
				}
			}

			globalSubdomains = append(globalSubdomains, finishedSub)
		}
	}

	re_next := regexp.MustCompile("<a id=\"next\" style=\".*\" href=\"(.*)\">&rarr;</a>")
	match1 := re_next.FindStringSubmatch(src)

	if len(match1) > 0 {
		enumerate(state, match1[1], domain)
	}

	return nil
}

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {
	var result helper.Result

	// Query using first page. Everything from there would be recursive
	err := enumerate(state, "http://archive.is/*."+domain, domain)
	if err != nil {
		result.Subdomains = globalSubdomains
		result.Error = err
		ch <- result
		return
	}

	result.Subdomains = globalSubdomains
	result.Error = nil
	ch <- result
}
