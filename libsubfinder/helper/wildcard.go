// 
// wildcard.go : Wildcard elimination method for eliminating false subdomains
// Written By : @ice3man (Nizamul Rana)
// 
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"net"
	"fmt"
	"sync"
	"strings"
)

// Method to eliminate Wildcard Is based on OJ Reeves Work on Gobuster Project
// github.com/oj/gobuster :-)
func InitializeWildcardDNS(state *State) bool {
	// Generate a random UUID and check if server responds with a valid
	// IP Address. If so, we are dealing with a wildcard DNS Server and will have
	// to work accordingly. 
	// In case of wildcard DNS, we will ignore any subdomain which has same IP
	// as our random UUID one
	uuid, _ := NewUUID()

	// Detection Logic adapted from GoBuster by @thecolonial
	wildcardIPs, err := net.LookupHost(fmt.Sprintf("%s.%s", uuid, state.Domain))

	if err == nil{
		state.IsWildcard = true
		state.WildcardIPs.AddRange(wildcardIPs)

		// We have found a wildcard DNS Server
		return true
	}

	return false
}

//
// CheckWildcardSubdomain : Checks if a given subdomain is a wildcard subdomain
// @argument state : Current application state
// @argument domain : Domain to find subdomains for
// @argument channel : Both request and response channel. If blank, it means a wildcard subdomain
func CheckWildcardSubdomain(state *State, domain string, channel chan string) {
	// TODO: Add custom resolver list support
	preparedSubdomain := <-channel + "." + domain
	ipAddress, err := net.LookupHost(preparedSubdomain)
	
	if err == nil {
		// No eror, let's see if it's a Wildcard subdomain
		if !state.WildcardIPs.ContainsAny(ipAddress) {
				channel <- preparedSubdomain
				return 
		} else {
				// This is likely a wildcard entry, skip it
				channel <- ""
				return 
		}
	} else {
		channel <- ""
		return 
	}

	channel <- ""
	return 
}

//
// RemoveWildcardSubdomains : Removes bad wildcard subdomains
// @argument subdomains : Subdomains list
// @return []string : List of valid subdomains
func RemoveWildcardSubdomains(state *State, subdomains []string) []string {
	wildcard := InitializeWildcardDNS(state)
	if wildcard == true {
		fmt.Printf("\n\n%s[!]%s Wildcard DNS Detected ! False Positives are likely :-(\n\n", Cyan, Reset)
	}

	var validSubdomains []string

    var wg sync.WaitGroup
	var channel = make(chan string)
	
	for i := 0; i < state.Threads; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			CheckWildcardSubdomain(state, state.Domain, channel)
		}()
	} 

	for _, entry := range subdomains {
		// Get the subdomain. Some complex logic here :-) lol
		sub := strings.Join(strings.Split(entry, ".")[:2][:], ".")
		channel <- sub
	}

	for _, _ = range subdomains {
		result := <-channel
		if state.Verbose == true {
			fmt.Printf("\n[-] %s", result)
		}
		if result != "" {
			validSubdomains = append(validSubdomains, result)
		}
	}

	return validSubdomains
}