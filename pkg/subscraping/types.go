package subscraping

import (
	"context"
	"net/http"
	"time"

	"github.com/projectdiscovery/ratelimit"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

type CtxArg string

const (
	CtxSourceArg CtxArg = "source"
)

type CustomRateLimit struct {
	Custom mapsutil.SyncLockMap[string, uint]
}

// BasicAuth request's Authorization header
type BasicAuth struct {
	Username string
	Password string
}

// Statistics contains statistics about the scraping process
type Statistics struct {
	TimeTaken time.Duration
	Requests  int
	Errors    int
	Results   int
	Skipped   bool
}

// KeyRequirement represents the API key requirement level for a source
type KeyRequirement int

const (
	NoKey KeyRequirement = iota
	OptionalKey
	RequiredKey
)

// Source is an interface inherited by each passive source
type Source interface {
	// Run takes a domain as argument and a session object
	// which contains the extractor for subdomains, http client
	// and other stuff.
	Run(context.Context, string, *Session) <-chan Result

	// Name returns the name of the source. It is preferred to use lower case names.
	Name() string

	// IsDefault returns true if the current source should be
	// used as part of the default execution.
	IsDefault() bool

	// HasRecursiveSupport returns true if the current source
	// accepts subdomains (e.g. subdomain.domain.tld),
	// not just root domains.
	HasRecursiveSupport() bool

	// KeyRequirement returns the API key requirement level for this source
	KeyRequirement() KeyRequirement

	// NeedsKey returns true if the source requires an API key.
	// Deprecated: Use KeyRequirement() instead for more granular control.
	NeedsKey() bool

	AddApiKeys([]string)

	// Statistics returns the scrapping statistics for the source
	Statistics() Statistics
}

// SubdomainExtractor is an interface that defines the contract for subdomain extraction.
type SubdomainExtractor interface {
	Extract(text string) []string
}

// Session is the option passed to the source, an option is created
// uniquely for each source.
type Session struct {
	//SubdomainExtractor
	Extractor SubdomainExtractor
	// Client is the current http client
	Client *http.Client
	// Rate limit instance
	MultiRateLimiter *ratelimit.MultiLimiter
	// Timeout is the timeout in seconds for requests
	Timeout int
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
