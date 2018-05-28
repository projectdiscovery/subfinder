//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A Parser for subdomains from Riddler
package riddler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"errors"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

type authentication struct {
	Response struct {
		User struct {
			Authentication_token string `json:"authentication_token"`
		} `json:"user"`
	} `json:"response"`
}

type host struct {
	Host string `json:"host"`
}

var hostResponse []host

var auth authentication

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {
	var result helper.Result
	result.Subdomains = subdomains

	hc := http.Client{}

	var data = []byte(`{"email":"` + state.ConfigState.RiddlerEmail + `", "password":"` + state.ConfigState.RiddlerPassword + `"}`)

	// Create a post request to get subdomain data
	req, err := http.NewRequest("POST", "https://riddler.io/auth/login", bytes.NewBuffer(data))
	req.Header.Add("Content-Type", "application/json")

	resp, err := hc.Do(req)

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	err = json.Unmarshal([]byte(body), &auth)
	if err != nil {
		result.Subdomains = subdomains
		result.Error = err
		ch <- result
		return
	}
  
  if auth.Response.User.Authentication_token == "" {
		result.Error = errors.New("failed to get authentication token")
		ch <- result
		return
	}
  
  data = []byte(`{"query":"pld:` + domain + `", "output":"host", "limit":500}`)

	req, err = http.NewRequest("POST", "https://riddler.io/api/search", bytes.NewBuffer(data))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authentication-Token", auth.Response.User.Authentication_token)

	resp, err = hc.Do(req)

	// Get the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Error = err
		ch <- result
		return
	}

	err = json.Unmarshal([]byte(body), &hostResponse)
	if err != nil {
		result.Subdomains = subdomains
		result.Error = err
		ch <- result
		return
	}

	for _, host := range hostResponse {

		subdomain := host.Host
		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sRIDDLER%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[RIDDLER] %s", subdomains)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
