//
// misc.go : contains misc helper function
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/subfinder/urlx"
)

// Result is the Current result structure
type Result struct {
	Subdomains []string // Subdomains found
	Error      error    // Any error that has occurred
}

// Domain structure
type Domain struct {
	IP   string
	Fqdn string
}

// NewUUID generates a random UUID according to RFC 4122
// Taken from : https://play.golang.org/p/4FkNSiUDMg
//
// Used for bruteforcing and detection of Wildcard Subdomains :-)
func NewUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// Unique Returns unique items in a slice
// Adapted from http://www.golangprograms.com/remove-duplicate-values-from-slice.html
func Unique(elements []string) []string {
	// Use map to record duplicates as we find them.
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	// Return the new slice.
	return result
}

// SubdomainExists checks if a key exists in an array
func SubdomainExists(key string, values []string) bool {
	for _, data := range values {
		if key == data {
			return true
		}
	}
	return false
}

// ExtractSubdomains extracts a subdomain from a big blob of text
func ExtractSubdomains(text, domain string) (urls []string) {
	allUrls := urlx.ExtractSubdomains(text, domain)

	return Validate(domain, allUrls)
}

//Validate returns valid subdomains found ending with target domain
func Validate(domain string, strslice []string) (subdomains []string) {
	for _, entry := range strslice {
		if strings.HasSuffix(entry, "."+domain) {
			subdomains = append(subdomains, entry)
		}
	}

	return subdomains
}
