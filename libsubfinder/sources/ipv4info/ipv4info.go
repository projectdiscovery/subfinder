//
// Written By : @Mzack9999
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

// Package ipv4info is a golang client for Ipv4Info
package ipv4info

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"

	"github.com/subfinder/subfinder/libsubfinder/helper"
)

// all subdomains found
var subdomains []string

// Query function returns all subdomains found using the service.
func Query(args ...interface{}) interface{} {

	domain := args[0].(string)
	state := args[1].(*helper.State)

	resp, err := helper.GetHTTPResponse("http://ipv4info.com/search/"+domain, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}
	src := string(body)

	// Get IP address page token
	regxTokens := regexp.MustCompile("/ip-address/(.*)/" + domain)
	matchTokens := regxTokens.FindAllString(src, -1)

	if len(matchTokens) == 0 {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	token := matchTokens[0]

	resp, err = helper.GetHTTPResponse("http://ipv4info.com"+token, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	// Get the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	src = string(body)

	// Get DNS address page token
	regxTokens = regexp.MustCompile("/dns/(.*?)/" + domain)
	matchTokens = regxTokens.FindAllString(src, -1)
	if len(matchTokens) == 0 {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	token = matchTokens[0]

	resp, err = helper.GetHTTPResponse("http://ipv4info.com"+token, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
			return subdomains
		}
	}
	// Get the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	src = string(body)

	// Get First Subdomains page token
	regxTokens = regexp.MustCompile("/subdomains/(.*?)/" + domain)
	matchTokens = regxTokens.FindAllString(src, -1)
	if len(matchTokens) == 0 {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	token = matchTokens[0]

	// Get first subdomains page
	resp, err = helper.GetHTTPResponse("http://ipv4info.com"+token, state.Timeout)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}
	// Get the response body
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		if !state.Silent {
			fmt.Printf("\nipv4info: %v\n", err)
		}
		return subdomains
	}

	src = string(body)

	additionalSubdomains := extractSubdomains(domain, src, state)
	subdomains = append(subdomains, additionalSubdomains...)
	nextPage := 1

	for {
		regxTokens := regexp.MustCompile("/subdomains/.*/page" + strconv.Itoa(nextPage) + "/" + domain + ".html")
		matchTokens := regxTokens.FindAllString(src, -1)
		if len(matchTokens) == 0 {
			break
		}
		token = matchTokens[0]

		resp, err = helper.GetHTTPResponse("http://ipv4info.com"+token, state.Timeout)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nipv4info: %v\n", err)
			}
			return subdomains
		}
		// Get the response body
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			if !state.Silent {
				fmt.Printf("\nipv4info: %v\n", err)
			}
			return subdomains
		}
		src = string(body)
		additionalSubdomains := extractSubdomains(domain, src, state)
		subdomains = append(subdomains, additionalSubdomains...)
		nextPage++
	}

	return subdomains
}

func extractSubdomains(domain, text string, state *helper.State) (subdomains []string) {
	match := helper.ExtractSubdomains(text, domain)

	for _, subdomain := range match {
		if helper.SubdomainExists(subdomain, subdomains) == false {
			if state.Verbose == true {
				if state.Color == true {
					fmt.Printf("\n[%sIpv4Info%s] %s", helper.Red, helper.Reset, subdomain)
				} else {
					fmt.Printf("\n[Ipv4Info] %s", subdomain)
				}
			}

			subdomains = append(subdomains, subdomain)
		}
	}

	return subdomains
}
