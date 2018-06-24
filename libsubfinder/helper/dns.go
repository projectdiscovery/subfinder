//
// dns.go : DNS helper functions for subfinder
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"fmt"
	"os"

	"github.com/bogdanovich/dns_resolver"
)

// Resolver is a global dns_resolver object
var Resolver *dns_resolver.DnsResolver

// ResolveHost resolves a host using dns_resolver lib
func ResolveHost(host string) (ips []string, err error) {
	// In case of i/o timeout
	Resolver.RetryTimes = 5

	ip, err := Resolver.LookupHost(host)
	if err != nil {
		return []string{}, err
	}

	var retIPs []string
	for _, host := range ip {
		retIPs = append(retIPs, host.String())
	}

	return retIPs, nil
}

// CheckWildcard checks if a ip result contains wildcards
func CheckWildcard(state *State, ips []string) (result bool) {
	for _, ip := range ips {
		for _, wildcardIP := range state.WildcardIP {
			if ip == wildcardIP {
				return true
			}
		}
	}

	// Not wildcard
	return false
}

// InitWildcard checks if a host returns wildcard ips and returns status with ips returned
func InitWildcard(domain string) (result bool, ips []string) {
	UUIDs := make([]string, 4)

	// Generate 4 random UUIDs
	for i := 0; i < 4; i++ {
		uuid, err := NewUUID()
		if err != nil {
			fmt.Printf("\nerror: %v\n", err)
			os.Exit(1)
		}
		UUIDs[i] = uuid
	}

	for _, uid := range UUIDs {
		attempt := fmt.Sprintf("%s.%s", uid, domain)

		// Currently we check only A records. GoBuster also does that
		// I don't think checking both A and CNAME checking is necessary
		ips, err := ResolveHost(attempt)
		if err != nil {
			continue
		}

		if len(ips) > 0 {
			return true, ips
		}
	}

	return false, ips
}
