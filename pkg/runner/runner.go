package runner

import (
	"bufio"
	"io"
	"os"
	"path"

	"github.com/projectdiscovery/subfinder/pkg/passive"
	"github.com/projectdiscovery/subfinder/pkg/resolve"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	passiveAgent   *passive.Agent
	resolverClient *resolve.Resolver
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{options: options}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine()

	// Initialize the active subdomain enumeration engine
	err := runner.initializeActiveEngine()
	if err != nil {
		return nil, err
	}

	return runner, nil
}

// RunEnumeration runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumeration() error {
	// Check if only a single domain is sent as input. Process the domain now.
	if r.options.Domain != "" {
		return r.EnumerateSingleDomain(r.options.Domain, r.options.Output, true)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomains(f)
		f.Close()
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomains(os.Stdin)
	}
	return nil
}

// EnumerateMultipleDomains enumerates subdomains for multiple domains
// We keep enumerating subdomains for a given domain until we reach an error
func (r *Runner) EnumerateMultipleDomains(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	var scanned int = 0
	for scanner.Scan() {
		var isFirstRun bool = (scanned == 0)

		domain := scanner.Text()
		if domain == "" {
			continue
		}

		outputFile := ""
		if r.options.Output != "" {
			outputFile = path.Join(r.options.OutputDirectory, r.options.Output)
		}

		// the first enumeration will overwrite the output file,
		// successive enumerations will append the results.
		err := r.EnumerateSingleDomain(domain, outputFile, isFirstRun)
		if err != nil {
			return err
		}
		scanned++
	}
	return nil
}
