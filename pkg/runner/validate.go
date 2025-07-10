package runner

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Check if domain, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if len(options.Domain) == 0 && options.DomainsFile == "" && !options.Stdin {
		return errors.New("no input list provided")
	}

	// Both verbose and silent flags were used
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	// Validate threads and options
	if options.Threads == 0 {
		return errors.New("threads cannot be zero")
	}
	if options.Timeout == 0 {
		return errors.New("timeout cannot be zero")
	}

	// Always remove wildcard with hostip
	if options.HostIP && !options.RemoveWildcard {
		return errors.New("hostip flag must be used with RemoveWildcard option")
	}

	if options.Match != nil {
		options.matchRegexes = make([]*regexp.Regexp, len(options.Match))
		var err error
		for i, re := range options.Match {
			if options.matchRegexes[i], err = regexp.Compile(stripRegexString(re)); err != nil {
				return errors.New("invalid value for match regex option")
			}
		}
	}
	if options.Filter != nil {
		options.filterRegexes = make([]*regexp.Regexp, len(options.Filter))
		var err error
		for i, re := range options.Filter {
			if options.filterRegexes[i], err = regexp.Compile(stripRegexString(re)); err != nil {
				return errors.New("invalid value for filter regex option")
			}
		}
	}

	sources := mapsutil.GetKeys(passive.NameSourceMap)
	for source := range options.RateLimits.AsMap() {
		if !sliceutil.Contains(sources, source) {
			return fmt.Errorf("invalid source %s specified in -rls flag", source)
		}
	}
	return nil
}
func stripRegexString(val string) string {
	val = strings.ReplaceAll(val, ".", "\\.")
	val = strings.ReplaceAll(val, "*", ".*")
	return fmt.Sprint("^", val, "$")
}

// ConfigureOutput configures the output on the screen
func (options *Options) ConfigureOutput() {
	// If the user desires verbose output, show verbose output
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
