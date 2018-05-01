//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Baidu Subdomain Discovery
package baidu

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains
	resp, err := helper.GetHTTPResponse("https://www.baidu.com/s?rn=100&pn=0&wd=site:" + state.Domain +"&oq=site:" + state.Domain, state.Timeout)
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
	
	re := regexp.MustCompile(`(?m)(\w+\.)+` + state.Domain)
	match := re.FindAllString(src, -1)
	for _, subdomain := range match {

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sBaidu%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[Baidu] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}
	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
