//
// Written By : @CaptainFreak (Shoeb Patel)
//
// Distributed Under MIT License
// Copyrights (C) 2018 CaptainFreak
//

// Package urlscan is a golang client for urlscan content discovery
package urlscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

type response struct {
	Message string
	ResultLink string
}

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	var uniqueSubdomains []string
	var initialSubdomains []string
	var hostResponse response
	// Get key for performing HTTP POST request
	key := state.ConfigState.UrlScanKey

	if key == "" {
		return subdomains
	}

	// Create JSON Get body
	var request = []byte(`{\"url\": `+domain+`, \"public\": \"off\"}`)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://urlscan.io/api/v1/scan/", bytes.NewBuffer(request))
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nurlscan: %v\n", err)
		}
		return subdomains
	}

	// Set content type as application/json
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Key", key)

	resp, err := client.Do(req)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nurlscan: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nurlscan: %v\n", err)
		}
		return subdomains
	}

	err = json.Unmarshal([]byte(body), &hostResponse)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nurlscan: %v\n", err)
		}
		return subdomains
	}

	// Make a http GET request to get results
	resultResp, err := helper.GetHTTPResponse(hostResponse.ResultLink, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nurlscan: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	respBody, err := ioutil.ReadAll(resultResp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nurlscan: %v\n", err)
		}
		return subdomains
	}

	urlscanData := helper.ExtractSubdomains(string(respBody), domain)

	for _, subdomain := range urlscanData {
		if helper.SubdomainExists(subdomain, subdomains) == false {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sUrlscan%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Urlscan] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
		}
	}
	return subdomains
}
