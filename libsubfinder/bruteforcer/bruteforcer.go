//
// bruteforcer.go : Helper functions for bruteforcer module
// Written By : @codingo
//		@ice3man
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package bruteforcer

import (
	"fmt"
	"net"

	"github.com/ice3man543/subfinder/libsubfinder/helper"
)

func CheckDNSEntry(state *helper.State, domain string, channel chan string) {
	// Create a prepared subdomain
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
}
