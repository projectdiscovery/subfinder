//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package riddler is a Parser for subdomains from Riddler
package riddler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

type authentication struct {
	Response struct {
		User struct {
			AuthenticationToken string `json:"authentication_token"`
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
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	if state.ConfigState.RiddlerEmail == "" || state.ConfigState.RiddlerPassword == "" {
		return subdomains
	}

	hc := http.Client{}

	var data = []byte(`{"email":"` + state.ConfigState.RiddlerEmail + `", "password":"` + state.ConfigState.RiddlerPassword + `"}`)

	// Create a post request to get subdomain data
	req, err := http.NewRequest("POST", "https://riddler.io/auth/login", bytes.NewBuffer(data))
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
	}

	err = json.Unmarshal([]byte(body), &auth)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
	}

	if auth.Response.User.AuthenticationToken == "" {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", "failed to get authentication token")
		}
		return subdomains
	}

	data = []byte(`{"query":"pld:` + domain + `", "output":"host", "limit":500}`)

	req, err = http.NewRequest("POST", "https://riddler.io/api/search", bytes.NewBuffer(data))
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authentication-Token", auth.Response.User.AuthenticationToken)

	resp, err = hc.Do(req)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", "failed to get authentication token")
		}
		return subdomains
	}

	err = json.Unmarshal([]byte(body), &hostResponse)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nriddler: %v\n", err)
		}
		return subdomains
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

	return subdomains
}
