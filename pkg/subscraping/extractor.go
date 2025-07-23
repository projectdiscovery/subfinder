package subscraping

import (
	"regexp"
	"strings"
)

// RegexSubdomainExtractor is a concrete implementation of the SubdomainExtractor interface, using regex for extraction.
type RegexSubdomainExtractor struct {
	extractor *regexp.Regexp
}

// NewSubdomainExtractor creates a new regular expression to extract
// subdomains from text based on the given domain.
func NewSubdomainExtractor(domain string) (*RegexSubdomainExtractor, error) {
	extractor, err := regexp.Compile(`(?i)[a-zA-Z0-9\*_.-]+\.` + domain)
	if err != nil {
		return nil, err
	}
	return &RegexSubdomainExtractor{extractor: extractor}, nil
}

// Extract implements the SubdomainExtractor interface, using the regex to find subdomains in the given text.
func (re *RegexSubdomainExtractor) Extract(text string) []string {
	matches := re.extractor.FindAllString(text, -1)
	for i, match := range matches {
		matches[i] = strings.ToLower(match)
	}
	return matches
}
