// 
// ptrarchive.go : A PTRArchive subdomain parser in golang
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package ptrarchive

import (
	"io/ioutil"
	"fmt"
	"regexp"

	"subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string 

// 
// Query : Queries awesome DNSDumpster service for subdomains
// @param state : current application state, holds all information found
//
func Query(state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to Netcraft
	resp, err := helper.GetHTTPResponse("http://ptrarchive.com/tools/search2.htm?label="+state.Domain+"&date=ALL", state.Timeout)
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

	// Parse Subdomains found
	Regex, _ := regexp.Compile("] (.*) \\[")
	match := Regex.FindAllStringSubmatch(src, -1)
    
    // String to hold initial subdomains
    var initialSubs []string

   	for _, data := range match {
   		initialSubs = append(initialSubs, data[1])
	}

	validSubdomains := helper.Validate(state, initialSubs)

	for _, subdomain := range validSubdomains {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sPTRARCHIVE%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[PTRARCHIVE] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
    }


  	result.Subdomains = subdomains
	result.Error = nil
	ch <-result
}
