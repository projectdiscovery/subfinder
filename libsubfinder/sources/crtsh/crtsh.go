//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package crtsh is a Golang based client for CRT.SH Parsing
package crtsh

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

type crtshObject struct {
	NameValue string `json:"name_value"`
}

var crtshData []crtshObject

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	resp, err := helper.GetHTTPResponse("https://crt.sh/?q=%25."+domain+"&output=json", state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncrtsh: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncrtsh: %v\n", err)
		}
		return subdomains
	}

	if strings.Contains(string(respBody), "The requested URL / was not found on this server.") {
		if !state.Silent {
			fmt.Printf("\ncrtsh: %v\n", err)
		}
		return subdomains
	}

	// Convert Response Body to string and then replace }{ to },{
	// This is done in order to enable parsing of JSON format employed by
	// crt.sh
	correctFormat := strings.Replace(string(respBody), "}{", "},{", -1)

	// Now convert it into a json array like this
	// [
	// 		{abc},
	//		{abc}
	// ]
	jsonOutput := "[" + correctFormat + "]"

	// Decode the json format
	err = json.Unmarshal([]byte(jsonOutput), &crtshData)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncrtsh: %v\n", err)
		}
		return subdomains
	}

	// Append each subdomain found to subdomains array
	for _, subdomain := range crtshData {

		// Fix Wildcard subdomains containg asterisk before them
		if strings.Contains(subdomain.NameValue, "*.") {
			subdomain.NameValue = strings.Split(subdomain.NameValue, "*.")[1]
		}

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sCRT.SH%s] %s", helper.Red, helper.Reset, subdomain.NameValue)
			} else {
				fmt.Printf("\n[CRT.SH] %s", subdomain.NameValue)
			}
		}

		subdomains = append(subdomains, subdomain.NameValue)
	}

	return subdomains
}
