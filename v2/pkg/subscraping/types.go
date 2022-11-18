package subscraping

import (
	"net/http"
	"regexp"

	"github.com/projectdiscovery/ratelimit"
)

// BasicAuth request's Authorization header
type BasicAuth struct {
	Username string
	Password string
}

// Session is the option passed to the source, an option is created
// uniquely for each source.
type Session struct {
	// Extractor is the regex for subdomains created for each domain
	Extractor *regexp.Regexp
	// Client is the current http client
	Client *http.Client
	// Rate limit instance
	RateLimiter *ratelimit.Limiter
}

// Result is a result structure returned by a source
type Result struct {
	Type   ResultType
	Source string
	Value  string
	Error  error
}

// ResultType is the type of result returned by the source
type ResultType int

// Types of results returned by the source
const (
	Subdomain ResultType = iota
	Error
)
