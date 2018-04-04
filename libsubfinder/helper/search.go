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
	MaxDomains			int 		// Max subdomains per page
	MaxPages			int 		// Max pages we should query

	CurrentPageNo		int 		// Current page we are checking
	CurrentRetries  	int 		// Retries we have already made

	PrevLinksFound		[]string 	// Links we have previously found
	CurrentSubdomains 	[]string 	// Subdomains we have already found on a page

	AllSubdomains		[]string 	// All Subdomains found so far
}

//
// CheckMaxSubdomains : Check if we have found maximum subdomains on the page
// @params config : Current configuration object
//
// @return true/false : If yes, true if no false
//
func CheckMaxSubdomains(config *BaseSearchConfiguration) (result bool) {
	// If we have no limit on max domains on pages
	if config.MaxDomains == 0 {
		return false
	}

	// If the number of subdomains on current page is >= max subdomains per page,
	// return true. 
	if len(config.CurrentSubdomains) >= config.MaxDomains {
		return true
	}

	return false
}

//
// CheckMaxPages : Check if we have found maximum pages per service
// @params config : Current configuration object
//
// @return true/false : If yes, true if no false
//
func CheckMaxPages(config *BaseSearchConfiguration) (result bool) {
	// If we have no limit on max pages
	if config.MaxPages == 0 {
		return false
	}

	// If the current page is >= Max Pages, return True
	if config.CurrentPageNo >= config.MaxPages {
		return true
	}

	return false
}
