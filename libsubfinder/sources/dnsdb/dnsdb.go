// 
// dnsdb.go : A dnsdb.org subdomain parsing engine in golang
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package dnsdb

import (
	"io/ioutil"
	"fmt"
	"regexp"
	"strings"

	"subfinder/libsubfinder/helper"
)


// 
// Query : Queries awesome DnsDB service for subdomains
// @param state : current application state, holds all information found
// 
// @return subdomain : String array containing subdomains found
// @return err : nil if successfull and error if failed
//
func Query(state *helper.State) (subdomains []string, err error) {

	resp, err := helper.GetHTTPResponse("https://www.dnsdb.org/f/"+state.Domain+".dnsdb.org/", 3000)
	if err != nil {
		return subdomains, err
	}

	// Get the response body
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return subdomains, err
	}

	body := string(resp_body)

	re := regexp.MustCompile("(?<=href=\").+?(?=\")|(?<=href=').+?(?=')")
    match := re.FindAllStringSubmatch(body, -1)
    
    for _, subdomain := range match {
    	// Dirty Logic
    	firstSubdomain := strings.Replace(subdomain[1], "https://", "", -1)
    	finishedSub := strings.Replace(firstSubdomain, ".dnsdb.org/", "", -1)

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[\033[31;1;4mDNSDB\033[0m] %s", finishedSub)
			} else {
				fmt.Printf("\n[DNSDB] %s", finishedSub)
			}
		}

		subdomains = append(subdomains, finishedSub)
    }

  	return subdomains, nil
}
