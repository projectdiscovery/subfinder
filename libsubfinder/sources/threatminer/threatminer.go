//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A ThreatMiner subdomain parser in golang
package threatminer

import (
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains

	// Make a http request to CertDB
	resp, err := helper.GetHTTPResponse("https://www.threatminer.org/getData.php?e=subdomains_container&q="+domain+"&t=0&rt=10&p=1", state.Timeout)
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
	Regex, _ := regexp.Compile("\"domain\\.php\\?q=([a-zA-Z0-9\\*_.-]+\\." + domain + ")")
	match := Regex.FindAllStringSubmatch(src, -1)

	for _, m := range match {

		// First Capturing group
		subdomain := m[1]

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sTHREATMINER%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[THREATMINER] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
