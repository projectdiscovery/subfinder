// 
// netcraft.go : Netcraft Scraping Engine in Golang
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
	"crypto/sha1"	// Required for netcraft challenge response
	"net/url"
	"net/http"
	"io"

	"subfinder/libsubfinder/helper"
)

// Contains all subdomains found
var globalSubdomains []string

var gCookies []*http.Cookie

// 
// Local function to recursively enumerate subdomains until no subdomains
// are left :-)
//
// @param baseUrl : Base URL is the URL with which to begin enumerating
//				In recursion, it will be used to pass next Subdomains Link
//
func enumerate(state *helper.State, baseUrl string) (err error) {

	// Make a http request to Netcraft
	resp, gCookies, err := helper.GetHTTPCookieResponse(baseUrl, gCookies, 3000)
	if err != nil {
		return err
	}

	// Check all cookies for netcraft_js_verification_challenge
	for i := 0; i < len(gCookies); i++ {
		var curCookie *http.Cookie = gCookies[i]
		if curCookie.Name == "netcraft_js_verification_challenge" {
			// Get the current challenge string
			challenge := url.QueryEscape(curCookie.Value)

			// Create a sha1 hash as response
			h := sha1.New()
			io.WriteString(h, challenge)
			response := fmt.Sprintf("%x", h.Sum(nil))

			respCookie := &http.Cookie{
				Name:   "netcraft_js_verification_response",
				Value:  response,
				Domain: ".netcraft.com",
			}

			gCookies = append(gCookies, respCookie)
		}
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
    
    // Finally, all subdomains found :-)
    return nil
}

// 
// Query : Queries awesome Netcraft service for subdomains
// @param state : current application state, holds all information found
// 
// @return subdomain : String array containing subdomains found
// @return err : nil if successfull and error if failed
//
func Query(state *helper.State) (subdomains []string, err error) {

	// Initialize global cookie holder
	gCookies = nil

	// Query using first page. Everything from there would be recursive
	err = enumerate(state, "https://searchdns.netcraft.com/?restriction=site+ends+with&host="+state.Domain+"&lookup=wait..&position=limited")
	if err != nil {
		return subdomains, err
	}

  	return globalSubdomains, nil
}
