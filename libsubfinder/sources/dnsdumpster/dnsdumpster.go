// 
// dnsdumpster.go : A Parser for subdomains from DNSDumpster
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package dnsdumpster

import (
	"io/ioutil"
	"fmt"
	"regexp"
	"strings"
	"net/http"
	"net/url"
	"net/http/cookiejar"

	"subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string 
var gCookies []*http.Cookie

// 
// Query : Queries awesome DNSDumpster service for subdomains
// @param state : current application state, holds all information found
//
func Query(state *helper.State, ch chan helper.Result) {
	// CookieJar to hold csrf cookie
	var curCookieJar *cookiejar.Jar
	curCookieJar, _ = cookiejar.New(nil)

	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to Netcraft
	resp, gCookies, err := helper.GetHTTPCookieResponse("https://dnsdumpster.com", gCookies, state.Timeout)
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

    re := regexp.MustCompile("<input type='hidden' name='csrfmiddlewaretoken' value='(.*)' />")
    match := re.FindAllStringSubmatch(src, -1)
    
    // CSRF Middleware token for POST Request
   	csrfmiddlewaretoken := match[0]

   	// Set cookiejar values
   	u, _ := url.Parse("https://dnsdumpster.com")
   	curCookieJar.SetCookies(u, gCookies)

   	hc := http.Client{Jar: curCookieJar}
	form := url.Values{}

    form.Add("csrfmiddlewaretoken", csrfmiddlewaretoken[1])
    form.Add("targetip", state.Domain)
 
    // Create a post request to get subdomain data
   	req, err := http.NewRequest("POST", "https://dnsdumpster.com", strings.NewReader(form.Encode()))

   	req.PostForm = form
    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Add("Referer", "https://dnsdumpster.com")
    req.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1")

    resp, err = hc.Do(req)

    // Get the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	src = string(body)

	// Find the table holding host records
	Regex, _ := regexp.Compile("<td class=\"col-md-4\">(.*\\..*\\..*)<br>")
	match = Regex.FindAllStringSubmatch(src, -1)
    
    // String to hold initial subdomains
    var initialSubs []string

   	for _, data := range match {
   		initialSubs = append(initialSubs, data[1])
	}

	validSubdomains := helper.Validate(state, initialSubs)

	for _, subdomain := range validSubdomains {
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sDNSDUMPSTER%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[DNSDUMPSTER] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
    }


  	result.Subdomains = subdomains
	result.Error = nil
	ch <-result
}
