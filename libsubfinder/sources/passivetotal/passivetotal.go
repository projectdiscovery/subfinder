//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Passive total Subdomain Discovery
package passivetotal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

type passivetotal_object struct {
	Subdomains []string `json:"subdomains"`
}

var passivetotal_data passivetotal_object

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result

	// We have recieved an API Key
	// Now, we will use passiveTotal API key to fetch subdomain info
	if state.ConfigState.PassivetotalUsername != "" && state.ConfigState.PassivetotalKey != "" {

		// Get credentials for performing HTTP Basic Auth
		username := state.ConfigState.PassivetotalUsername
		key := state.ConfigState.PassivetotalKey

		// Create JSON Get body
		var request = []byte(`{"query":"` + domain + `"}`)

		client := &http.Client{}
		req, err := http.NewRequest("GET", "https://api.passivetotal.org/v2/enrichment/subdomains", bytes.NewBuffer(request))
		req.SetBasicAuth(username, key)

		// Set content type as application/json
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			result.Subdomains = subdomains
			result.Error = err
			ch <- result
			return
		}

		// Get the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			result.Subdomains = subdomains
			result.Error = err
			ch <- result
			return
		}

		// Decode the json format
		err = json.Unmarshal([]byte(body), &passivetotal_data)
		if err != nil {
			result.Subdomains = subdomains
			result.Error = err
			ch <- result
			return
		}

		// Append each subdomain found to subdomains array
		for _, subdomain := range passivetotal_data.Subdomains {
			finalSubdomain := subdomain + "." + domain

			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sPASSIVETOTAL%s] %s", helper.Red, helper.Reset, finalSubdomain)
				} else {
					fmt.Printf("\n[PASSIVETOTAL] %s", finalSubdomain)
				}
			}

			subdomains = append(subdomains, finalSubdomain)
		}

		result.Subdomains = subdomains
		result.Error = nil
		ch <- result
		return
	} else {
		result.Subdomains = subdomains
		result.Error = nil
		ch <- result
		return
	}
}
