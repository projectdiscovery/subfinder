// 
// hackertaget.go : A golang based Hackertarget subdomains search client
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package hackertarget

import (
	"io/ioutil"
	"strings"
	"bufio"
	"fmt"

	"subfinder/libsubfinder/helper"
)

// 
// Query : Queries awesome Hackertarget subdomain search service
// @param state : current application state, holds all information found
// 
// @return subdomain : String array containing subdomains found
// @return err : nil if successfull and error if failed
//
func Query(state *helper.State) (subdomains []string, err error) {

	resp, err := helper.GetHTTPResponse("https://api.hackertarget.com/hostsearch/?q="+state.Domain, 3000)
	if err != nil {
		return subdomains, err
	}

	// Get the response body
	resp_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return subdomains, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(resp_body)))
	for scanner.Scan() {
		subdomain := strings.Split(scanner.Text(), ",")[0]
		subdomains = append(subdomains, subdomain)

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[\033[31;1;4mHACKERTARGET\033[0m] %s", subdomain)
			} else {
				fmt.Printf("\n[HACKERTARGET] %s", subdomain)
			}
		}
	}

	return subdomains, nil
}
