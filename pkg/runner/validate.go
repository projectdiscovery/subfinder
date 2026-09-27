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
	if options.Threads <= 0 {
		return errors.New("threads must be positive")
	}

	if options.Timeout == 0 {
		return errors.New("timeout cannot be zero")
	}

	// Always remove wildcard with hostip
	if options.HostIP && !options.RemoveWildcard {
		return errors.New("hostip flag must be used with RemoveWildcard option")
	}

	// The per-source results limit cannot be negative.
	if options.MaxResults < 0 {
		return fmt.Errorf("max-results cannot be negative")
	}

	// The response body size limit cannot be negative.
	if options.MaxResponseBodySize < 0 {
		return fmt.Errorf("response-size-read cannot be negative")
	}

	if err := options.compileFilters(); err != nil {
		return err
	}

	sources := mapsutil.GetKeys(passive.NameSourceMap)
	for source := range options.RateLimits.AsMap() {
		if !sliceutil.Contains(sources, source) {
			return fmt.Errorf("invalid source %s specified in -rls flag", source)
		}
	}
	return nil
}

// compileFilters is also called by NewRunner so SDK users do not need to parse
// command-line options to initialize their result filters.
func (options *Options) compileFilters() error {
	for _, group := range []struct {
		name     string
		patterns []string
		regexes  []string
		target   *[]*regexp.Regexp
	}{
		{"match", options.Match, options.MatchRegex, &options.matchRegexes},
		{"filter", options.Filter, options.FilterRegex, &options.filterRegexes},
	} {
		*group.target = nil
		if group.patterns != nil || group.regexes != nil {
			*group.target = make([]*regexp.Regexp, 0, len(group.patterns)+len(group.regexes))
		}
		for _, pattern := range group.patterns {
			re, err := regexp.Compile(stripRegexString(pattern))
			if err != nil {
				return fmt.Errorf("invalid value for %s option %q: %w", group.name, pattern, err)
			}
			*group.target = append(*group.target, re)
		}
		for _, pattern := range group.regexes {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid value for %s-regex option %q: %w", group.name, pattern, err)
			}
			*group.target = append(*group.target, re)
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
