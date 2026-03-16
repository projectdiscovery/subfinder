package runner

import (
	"io"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

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
	// RateLimit is the global queries per second limit
	RateLimit        int
	// RateLimitMinute is the global queries per minute limit
	RateLimitMinute  int
	// SourceRateLimits is the per-source rate limit
	SourceRateLimits goflags.StringSlice
}
