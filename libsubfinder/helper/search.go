//
// search.go : Contains helper functions for search engine logic
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

// Configuration Structure which contains configuration for each
// search engine.
type BaseSearchConfiguration struct {
	MaxDomains int // Max subdomains per page
	MaxPages   int // Max pages we should query

	CurrentPageNo  int // Current page we are checking
	CurrentRetries int // Retries we have already made

	PrevLinksFound    []string // Links we have previously found
	CurrentSubdomains []string // Subdomains we have already found on a page

	AllSubdomains []string // All Subdomains found so far
}

// CheckMaxSubdomains checks if maximum number of domains was found.
func CheckMaxSubdomains(config *BaseSearchConfiguration) bool {
	// If we have no limit on max domains on pages
	if config.MaxDomains == 0 {
		return false
	}

	return len(config.CurrentSubdomains) >= config.MaxDomains
}

// CheckMaxPages checks if maximum number of pages per service was found.
func CheckMaxPages(config *BaseSearchConfiguration) bool {
	// If we have no limit on max pages
	if config.MaxPages == 0 {
		return false
	}

	return config.CurrentPageNo >= config.MaxPages
}
