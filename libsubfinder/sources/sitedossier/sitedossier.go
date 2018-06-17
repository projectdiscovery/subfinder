//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Sitedossier Scraping Engine in Golang
package sitedossier

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"time"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// Contains all subdomains found
var globalSubdomains []string

func enumerate(state *helper.State, baseUrl string, domain string) (err error) {
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

	re := helper.SubdomainRegex(domain)
	match := re.FindAllStringSubmatch(src, -1)

	for _, subdomain := range match {
		finishedSub := subdomain[0]

		if helper.SubdomainExists(finishedSub, globalSubdomains) == false {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sSITEDOSSIER%s] %s", helper.Red, helper.Reset, finishedSub)
				} else {
					fmt.Printf("\n[SITEDOSSIER] %s", finishedSub)
				}
			}

			globalSubdomains = append(globalSubdomains, finishedSub)
		}
	}

	time.Sleep(time.Duration((3 + rand.Intn(5))) * time.Second)

	re_next := regexp.MustCompile("<a href=\"(.*)\"><b>.*</b></a><br>")
	match1 := re_next.FindStringSubmatch(src)

	if len(match1) > 0 {
		enumerate(state, "http://www.sitedossier.com"+match1[1], domain)
	}

	return nil
}

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {
	var result helper.Result

	// Query using first page. Everything from there would be recursive
	err := enumerate(state, "http://www.sitedossier.com/parentdomain/"+domain, domain)
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
