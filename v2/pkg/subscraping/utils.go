package subscraping

import (
	"regexp"
	"sync"
)

var subdomainExtractorMutex = &sync.Mutex{}

// NewSubdomainExtractor creates a new regular expression to extract
// subdomains from text based on the given domain.
func NewSubdomainExtractor(domain string) (*regexp.Regexp, error) {
	subdomainExtractorMutex.Lock()
	defer subdomainExtractorMutex.Unlock()
	extractor, err := regexp.Compile(`[a-zA-Z0-9\*_.-]+\.` + domain)
	if err != nil {
		return nil, err
	}
	return extractor, nil
}

// Exists check if a key exist in a slice
func Exists(values []string, key string) bool {
	for _, v := range values {
		if v == key {
			return true
		}
	}
	return false
}
