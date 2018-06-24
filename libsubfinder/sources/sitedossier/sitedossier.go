//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package sitedossier is a Sitedossier Scraping Engine in Golang
package sitedossier

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"time"

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

	reNext := regexp.MustCompile("<a href=\"(.*)\"><b>.*</b></a><br>")
	match1 := reNext.FindStringSubmatch(src)

	if len(match1) > 0 {
		enumerate(state, "http://www.sitedossier.com"+match1[1], domain)
	}

	return nil
}

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Query using first page. Everything from there would be recursive
	err := enumerate(state, "http://www.sitedossier.com/parentdomain/"+domain, domain)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nsitedossier: %v\n", err)
		}
		return globalSubdomains
	}

	return globalSubdomains
}
