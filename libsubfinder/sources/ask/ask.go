// 
// ask.go : Ask subdomain parsing engine in golang
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package netcraft

import (
	"io/ioutil"
	"fmt"
	"regexp"
	"strings"

	"github.com/ice3man543/subfinder/libsubfinder/helper"
)

// Contains all subdomains found
var askConfiguration helper.BaseSearchConfiguration = {
	11,	// Max Subdomains
	0,	// Max Pages

	0,	// Current Page Number
	0,	// Current Retries

	[],	// Links found on previous page
	[], // Links found on current page

	[]	// All Subdomains found on current search engine
}

// 
// Local function to recursively enumerate subdomains until no subdomains
// are left :-)
//
// @param baseUrl : Base URL is the URL with which to begin enumerating
//				In recursion, it will be used to pass next Subdomains Link
//
func enumerate(state *helper.State, baseUrl string) (err error) {

	// Make a http request to Netcraft
	resp, err := helper.GetHTTPResponse(baseUrl, 3000)
	if err != nil {
		return err
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	src := string(body)

    re := regexp.MustCompile("<a href=\"http://toolbar.netcraft.com/site_report\\?url=(.*)\">")
    match := re.FindAllStringSubmatch(src, -1)
    
    for _, subdomain := range match {
    	// Dirty Logic
        finishedSub := strings.Split(subdomain[1], "//")[1]
		
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[\033[31;1;4mNETCRAFT\033[0m] %s", finishedSub)
			} else {
				fmt.Printf("\n[NETCRAFT] %s", finishedSub)
			}
		}

		globalSubdomains = append(globalSubdomains, finishedSub)
    }

    // we have another page full of juicy subdomains
    if strings.Contains(src, "Next page") {
    	// Checkout the link for the next page
    	re_next := regexp.MustCompile("<A href=\"(.*?)\"><b>Next page</b></a>")
    	match := re_next.FindStringSubmatch(src)

    	// Replace spaces with + characters in URL Query since they don't allow request to happen
    	finalQuery := strings.Replace(match[1], " ", "+", -1)
    	enumerate(state, "https://searchdns.netcraft.com"+finalQuery)
    }

    return nil
}

// 
// Query : Queries awesome Ask service for subdomains
// @param state : current application state, holds all information found
// 
// @return subdomain : String array containing subdomains found
// @return err : nil if successfull and error if failed
//
func Query(state *helper.State) (subdomains []string, err error) {

	// Query using first page. Everything from there would be recursive
	err = enumerate(state, "http://www.ask.com/web?q="+state.Domain+"&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination")
	if err != nil {
		return subdomains, err
	}

  	return globalSubdomains, nil
}
