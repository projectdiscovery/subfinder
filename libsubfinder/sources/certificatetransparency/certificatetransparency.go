//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package certificatetransparency is a golang client for Entrust Certificate Transparency
package certificatetransparency

import (
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	resp, err := helper.GetHTTPResponse("https://ctsearch.entrust.com/api/v1/certificates?fields=issuerCN,subjectO,issuerDN,issuerO,subjectDN,signAlg,san,publicKeyType,publicKeySize,validFrom,validTo,sn,ev,logEntries.logName,subjectCNReversed,cert&domain="+domain+"&includeExpired=true&exactMatch=false&limit=5000", state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertificatetransparency: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ncertificatetransparency: %v\n", err)
		}
		return subdomains
	}

	// suppress all %xx sequences with a space
	src := strings.Replace(string(body), "u003d", " ", -1)

	match := helper.ExtractSubdomains(src, domain)

	for _, subdomain := range match {
		if sort.StringsAreSorted(subdomains) == false {
			sort.Strings(subdomains)
		}

		insertIndex := sort.SearchStrings(subdomains, subdomain)
		if insertIndex < len(subdomains) && subdomains[insertIndex] == subdomain {
			continue
		}

		if state.Verbose == true {
			if state.Color == true {
				fmt.Printf("\n[%sEntrust-CTSearch%s] %s", helper.Red, helper.Reset, subdomain)
			} else {
				fmt.Printf("\n[Entrust-CTSearch] %s", subdomain)
			}
		}

		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}
