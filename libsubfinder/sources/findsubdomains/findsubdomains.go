// 
// findsubdomains.go : Golang driver from findsubdomains.com
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package findsubdomains

import (
	"io/ioutil"
	"fmt"
	"regexp"
	"strings"

	"github.com/ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string 

// 
// Query : Queries awesome Findsubdomains.com service for subdomains
// @param state : current application state, holds all information found
//
func Query(state *helper.State, ch chan helper.Result) {
	
	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to Netcraft
	resp, err := helper.GetHTTPResponse("https://findsubdomains.com/subdomains-of/"+state.Domain, state.Timeout)
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

    re := regexp.MustCompile("<a class=\"aggregated-link\" rel=\"nofollow\" href=\"(.*)\" target=\"_blank\">")
    match := re.FindAllStringSubmatch(src, -1)
    
    for _, subdomain := range match {
    	// Dirty Logic
        finishedSub := strings.Split(subdomain[1], "//")[1]
		
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sFINDSUBDOMAINS%s] %s", helper.Red, helper.Reset, finishedSub)
			} else {
				fmt.Printf("\n[FINDSUBDOMAINS] %s", finishedSub)
			}
		}

		subdomains = append(subdomains, finishedSub)
	}

  	result.Subdomains = subdomains
	result.Error = nil
	ch <-result
}
