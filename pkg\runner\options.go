package runner

import (
	"io"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
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
	ResultCallback     subscraping.OnResultCallback
	DisableUpdateCheck bool
	// RateLimit is the maximum number of http requests to be made per second (global)
	RateLimit int
	// RateLimitMinute is the maximum number of http requests to be made per minute (global)
	RateLimitMinute int
	// SourceRateLimits is a list of source rate limits (source=N/duration)
	SourceRateLimits goflags.StringSlice
}

// configureOutput configures the output logging levels to use.
func configureOutput(options *Options) {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
