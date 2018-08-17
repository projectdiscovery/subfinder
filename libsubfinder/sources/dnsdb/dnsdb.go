//
// Written By : @mehimansu (Himanshu Das)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package dnsdb is a Golang driver for dnsdb.org
package dnsdb

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
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
		if !state.Silent {
			fmt.Printf("\ndnsdb: %v\n", err)
		}
		return subdomains
	}
	if resp.StatusCode != 200 {
		err := fmt.Sprintf("Unexpected return status %d", resp.StatusCode)
		if !state.Silent {
			fmt.Printf("\ndnsdb: %v\n", err)
		}
		return subdomains
	}
	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ndnsdb: %v\n", err)
		}
		return subdomains
	}
	src := string(body)
	re := regexp.MustCompile("<a[^>]*?[^>]*>(.*?)</a>")
	match := re.FindAllStringSubmatch(src, -1)

	for _, subdomain := range match {
		stringSplit := strings.Split(subdomain[0], "\">")[1]
		finishedSub := strings.TrimRight(stringSplit, "</a>")

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
