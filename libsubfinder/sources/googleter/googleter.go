//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package googleter is a Golang based client for GoogleTER Parsing
package googleter

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

func makeRequest(token string, domain string, state *helper.State) (respBody []byte, err error) {
	requestURI := ""

	if token == "" {
		requestURI = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain=" + url.QueryEscape(domain) + "&include_expired=true&include_subdomains=true"
	} else {
		requestURI = "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?domain=" + url.QueryEscape(domain) + "&include_expired=true&include_subdomains=true&p=" + url.QueryEscape(token)
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", requestURI, nil)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ngoogleter: %v\n", err)
		}
		return respBody, nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1")
	req.Header.Add("Connection", "close")
	req.Header.Set("Referer", "https://transparencyreport.google.com/https/certificates")

	resp, err := client.Do(req)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ngoogleter: %v\n", err)
		}
		return respBody, nil
	}

	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ngoogleter: %v\n", err)
		}
		return respBody, nil
	}

	return respBody, nil
}

func printSubdomains(match [][]string, state *helper.State) {
	var finalSubdomain = ""
	for _, subdomain := range match {
		if !helper.SubdomainExists(subdomain[0], subdomains) {
			finalSubdomain = subdomain[0]
			if strings.Contains(subdomain[0], "*.") {
				finalSubdomain = strings.Split(subdomain[0], "*.")[1]
			}

			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sGoogleTER%s] %s", helper.Red, helper.Reset, finalSubdomain)
				} else {
					fmt.Printf("\n[GoogleTER] %s", finalSubdomain)
				}
			}

			subdomains = append(subdomains, finalSubdomain)
		}
	}
}

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	respBody, err := makeRequest("", domain, state)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\ngoogleter: %v\n", err)
		}
		return subdomains
	}

	var Token string

	metaRegex := regexp.MustCompile(`\[null,"(.*)",null,(.*),(.*)]`)
	matches := metaRegex.FindStringSubmatch(string(respBody))
	if len(matches) <= 1 {
		return subdomains
	}

	subdomainRegex := regexp.MustCompile(`([A-Za-z0-9]+\.)+` + domain)
	match := subdomainRegex.FindAllStringSubmatch(string(respBody), -1)
	printSubdomains(match, state)

	// In some weird cases, googleter returns specifc hashes embedded in the results.
	// We fall back to this regex in order to to find that token
	cryptoSHA2 := regexp.MustCompile(`\[null,"B05DFBBD58ECDB8D18100E6AA4DA0C64AECA148D41971942A8E2068375063759",null,(.*),(.*)]`)
	mcryptoSHA2 := cryptoSHA2.FindStringSubmatch(string(respBody))
	if len(mcryptoSHA2) >= 1 {
		Token = mcryptoSHA2[0]
	} else {
		cryptoSHA2CBC := regexp.MustCompile(`\[null,"A0315234520886D17581376D876B44FE0FADAD26CA47A9A0A1F4BA9BD8735947",null,(.*),(.*)]`)
		mcryptoSHA2CBC := cryptoSHA2CBC.FindStringSubmatch(string(respBody))
		if len(mcryptoSHA2CBC) >= 1 {
			Token = mcryptoSHA2[0]
		} else {
			Token = matches[1]
		}
	}

	MaxPages, _ := strconv.Atoi(matches[3])
	for i := 1; i <= MaxPages; i++ {
		respBody, err = makeRequest(Token, domain, state)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\ngoogleter: %v\n", err)
			}
			return subdomains
		}

		match := subdomainRegex.FindAllStringSubmatch(string(respBody), -1)
		printSubdomains(match, state)

		metaRegex2 := regexp.MustCompile(`\["(.*)",".*",null,(.*),(.*)]`)
		matches := metaRegex2.FindStringSubmatch(string(respBody))
		matches2 := metaRegex.FindStringSubmatch(string(respBody))
		if len(matches2) > 1 {
			Token = matches2[1]
		}
		if len(matches) > 1 {
			Token = matches[1]
		}

		maxPages, _ := strconv.Atoi(state.CurrentSettings.GoogleterPages)
		if i > maxPages {
			break
		}
	}

	return subdomains
}
