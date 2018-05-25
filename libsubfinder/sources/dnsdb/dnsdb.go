//
// Written By : @mehimansu (Himanshu Das)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Golang driver from dnsdb.org
package dnsdb

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to DnsDB
	resp, err := helper.GetHTTPResponse("http://www.dnsdb.org/f/"+domain+".dnsdb.org/", state.Timeout)
	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
		return subdomains
	}
	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
		return subdomains
	}
	src := string(body)
	re := regexp.MustCompile("<a[^>]*?[^>]*>(.*?)</a>")
	match := re.FindAllStringSubmatch(src, -1)

	for _, subdomain := range match {
		string_split := strings.Split(subdomain[0], "\">")[1]
		finishedSub := strings.TrimRight(string_split, "</a>")

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sDNSDB%s] %s", helper.Red, helper.Reset, finishedSub)
			} else {
				fmt.Printf("\n[DNSDB] %s", finishedSub)
			}
		}

		subdomains = append(subdomains, finishedSub)
	}
	return subdomains
}
