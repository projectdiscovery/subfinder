package subscraping

import (
	"context"
	"time"
)

const (
	NONE          = "none"
	KEY_SIMPLE    = "simple"
	KEY_MULTIPART = "multipart"
	TYPE_API      = "api"
	TYPE_ARCHIVE  = "archive"
	TYPE_CERT     = "cert"
	TYPE_CRAWL    = "crawl"
	TYPE_DNS      = "dns"
	TYPE_SCRAPE   = "scrape"
)

type ISource interface {
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

	// NeedsKey returns true if the source requires an API key
	NeedsKey() bool

	// AddApiKeys adds the API keys to the source if the source requires an API key
	AddApiKeys([]string)

	// KeyType returns the API key type of the source
	KeyType() string

	// SourceType returns the source type
	SourceType() string

	// Statistics returns the scrapping statistics for the source
	Statistics() Statistics
}

// Source is the basic source
type Source struct {
	TimeTaken time.Duration
	Results   int
	Errors    int
	Skipped   bool
}

func (s *Source) Name() string {
	return NONE
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) Run(ctx context.Context, domain string, session *Session) <-chan Result {
	return nil
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) KeyType() string {
	return NONE
}

func (s *Source) SourceType() string {
	return NONE
}

func (s *Source) Statistics() Statistics {
	return Statistics{
		Errors:    s.Errors,
		Results:   s.Results,
		TimeTaken: s.TimeTaken,
	}
}

// KeyApiSource is a source who needs an API key
type KeyApiSource struct {
	*Source
	keys []string
}

func (s *KeyApiSource) NeedsKey() bool {
	return true
}

func (s *KeyApiSource) AddApiKeys(keys []string) {
	s.keys = keys
}

func (s *KeyApiSource) ApiKeys() []string {
	return s.keys
}

func (s *KeyApiSource) KeyType() string {
	return KEY_SIMPLE
}

// CompositeKeyApiSource is a source who needs a composite secret key (username:password, token:secret...)
type MultiPartKeyApiSource struct {
	*Source
	keys []BasicAuth
}

func (s *MultiPartKeyApiSource) NeedsKey() bool {
	return true
}

func (s *MultiPartKeyApiSource) AddApiKeys(keys []string) {
	s.keys = CreateApiKeys(keys, func(k, v string) BasicAuth {
		return BasicAuth{k, v}
	})
}

func (s *MultiPartKeyApiSource) ApiKeys() []BasicAuth {
	return s.keys
}

func (s *MultiPartKeyApiSource) KeyType() string {
	return KEY_MULTIPART
}
