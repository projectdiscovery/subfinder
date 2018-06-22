//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A Golang based client
package sslcertificates

import (
	"fmt"
	"strings"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {
	domain := args[0].(string)
	state := args[1].(*helper.State)

	resp, err := helper.GetHTTPResponse("https://"+domain, state.Timeout)
	if err != nil {
		fmt.Printf("\nsslcertificates: %v\n", err)
		return subdomains
	}

	for _, cert := range resp.TLS.PeerCertificates {
		findSubdomains(cert.DNSNames, state)
	}

	return subdomains
}

func findSubdomains(list []string, state *helper.State) {
	for _, altname := range list {
		// Fix Wildcard subdomains containg asterisk before them
		if strings.Contains(altname, "*.") {
			altname = strings.Split(altname, "*.")[1]
		}

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sSSL Certificates%s] %s", helper.Red, helper.Reset, altname)
			} else {
				fmt.Printf("\n[SSL Certificates] %s", altname)
			}
		}

		subdomains = append(subdomains, altname)
	}
}
