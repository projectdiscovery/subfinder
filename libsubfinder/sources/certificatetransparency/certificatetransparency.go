//
// Written By : @Mzack9999 (Marco Rivoli)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// A golang client for Google Transparency Report
package certificatetransparency

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"sort"
	"strings"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(domain string, state *helper.State, ch chan helper.Result) {

	var result helper.Result
	result.Subdomains = subdomains

	resp, err := helper.GetHTTPResponse("https://ctsearch.entrust.com/api/v1/certificates?fields=issuerCN,subjectO,issuerDN,issuerO,subjectDN,signAlg,san,publicKeyType,publicKeySize,validFrom,validTo,sn,ev,logEntries.logName,subjectCNReversed,cert&domain="+domain+"&includeExpired=true&exactMatch=false&limit=5000", state.Timeout)
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

	// suppress all %xx sequences with a space
	src := strings.Replace(string(body), "u003d", " ", -1)

	re := regexp.MustCompile(`([a-z0-9]+\.)+` + domain)
	match := re.FindAllString(src, -1)

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

	result.Subdomains = subdomains
	result.Error = nil
	ch <- result
}
