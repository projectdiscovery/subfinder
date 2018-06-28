//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package certdb is a CertDB Subdomain parser in golang
package certdb

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Parser subdomains from SSL Certificate Information Page
func findSubdomains(link string, state *helper.State, channel chan []string) {
	var subdomainsfound []string

	resp, err := helper.GetHTTPResponse("https://certdb.com"+link, state.Timeout)
	if err != nil {
		channel <- subdomainsfound
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		channel <- subdomainsfound
		return
	}

	src := string(body)

	SubdomainRegex, err := regexp.Compile("<a href=\"https://certdb.com/domain/(.*)\"  target='_blank' class='link-underlined' >")
	if err != nil {
		channel <- subdomainsfound
		return
	}

	match := SubdomainRegex.FindAllStringSubmatch(src, -1)

	for _, link := range match {
		subdomainsfound = append(subdomainsfound, link[1])
	}

	channel <- subdomainsfound
}

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	// Make a http request to CertDB
	resp, err := helper.GetHTTPResponse("https://certdb.com/domain/"+domain, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertdb: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertdb: %v\n", err)
		}
		return subdomains
	}

	src := string(body)

	// Get links for all the SSL Certficates found
	Regex, _ := regexp.Compile("<a href=\"(.*)\" class=\"see-more-link\">See more →</a>")
	match := Regex.FindAllStringSubmatch(src, -1)

	var initialSubs []string
	var subsReturned []string

	channel := make(chan []string, len(match))

	for _, link := range match {
		go findSubdomains(link[1], state, channel)
	}

	for i := 0; i < len(match); i++ {
		subsReturned = <-channel

		initialSubs = append(initialSubs, subsReturned...)
	}

	for _, subdomain := range initialSubs {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sCERTDB%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[CERTDB] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}
