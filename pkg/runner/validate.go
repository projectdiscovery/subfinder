package runner

import (
	"errors"

	"github.com/projectdiscovery/subfinder/pkg/log"
)

// validateOptions validates the configuration options passed
func (options *Options) validateOptions() error {
	// Check if domain, list of domains, or stdin info was provided.
	// If none was provided, then return.
	if options.Domain == "" && options.DomainsFile == "" && !options.Stdin {
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

	// JSON cannot be used with hostIP
	if options.JSON && options.HostIP {
		return errors.New("hostip flag cannot be used with json flag")
	}

	// Always remove wildcard with hostip and json
	if options.HostIP && !options.RemoveWildcard {
		return errors.New("hostip flag must be used with RemoveWildcard option")
	}
	if options.JSON && !options.RemoveWildcard {
		return errors.New("JSON flag must be used with RemoveWildcard option")
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		log.MaxLevel = log.Verbose
	}
	if options.NoColor {
		log.UseColors = false
	}
	if options.Silent {
		log.MaxLevel = log.Silent
	}
}
