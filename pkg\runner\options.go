package runner

import (
	"io"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

// OnResultCallback is the callback function for results
type OnResultCallback func(s *subscraping.Result)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool
	NoColor            bool
	JSON               bool
	HostIP             bool
	Silent             bool
	ListSources        bool
	RemoveWildcard     bool
	CaptureSources     bool
	Stdin              bool
	Version            bool
	OnlyRecursive      bool
	All                bool
	Statistics         bool
	Threads            int
	Timeout            int
	MaxEnumerationTime int
	Domain             goflags.StringSlice
	DomainsFile        string
	Output             io.Writer
	OutputFile         string
	OutputDirectory    string
	Sources            goflags.StringSlice
	ExcludeSources     goflags.StringSlice
	APIKey             goflags.StringSlice
	Match              goflags.StringSlice
	Filter             goflags.StringSlice
	ResultCallback     OnResultCallback
	DisableUpdateCheck bool
	// Rate limiting options
	RateLimit        int
	RateLimitMinute  int
	SourceRateLimits goflags.StringSlice
}
