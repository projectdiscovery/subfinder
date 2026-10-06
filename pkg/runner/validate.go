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

	sources := mapsutil.GetKeys(passive.NameSourceMap)
	for source := range options.RateLimits.AsMap() {
		if !sliceutil.Contains(sources, source) {
			return fmt.Errorf("invalid source %s specified in -rls flag", source)
		}
	}
	return nil
}

// compileFilters runs in NewRunner rather than option validation so SDK
// callers, who never parse flags, get their filters applied too.
func (r *Runner) compileFilters() error {
	var err error
	if r.matchRegexes, err = compileRegexes("match", r.options.Match, r.options.MatchRegex); err != nil {
		return err
	}
	r.filterRegexes, err = compileRegexes("filter", r.options.Filter, r.options.FilterRegex)
	return err
}

func compileRegexes(option string, globs, regexes []string) ([]*regexp.Regexp, error) {
	// A non-nil empty glob list keeps its legacy meaning of matching nothing,
	// while an empty regex list behaves like an unset option.
	if globs == nil && len(regexes) == 0 {
		return nil, nil
	}
	compiled := make([]*regexp.Regexp, 0, len(globs)+len(regexes))
	for _, glob := range globs {
		re, err := regexp.Compile(stripRegexString(glob))
		if err != nil {
			return nil, fmt.Errorf("invalid value for %s option %q: %w", option, glob, err)
		}
		compiled = append(compiled, re)
	}
	for _, pattern := range regexes {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid value for %s-regex option %q: %w", option, pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
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
