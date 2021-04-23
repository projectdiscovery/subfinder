package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"path"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
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
func (r *Runner) RunEnumeration(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	// Check if only a single domain is sent as input. Process the domain now.
	if r.options.Domain != "" {
		// If output file specified, create file
		if r.options.OutputFile != "" {
			outputter := NewOutputter(r.options.JSON)
			file, err := outputter.createFile(r.options.OutputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}
			defer file.Close()

			outputs = append(outputs, file)
		}

		return r.EnumerateSingleDomain(ctx, r.options.Domain, outputs)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomains(ctx, f, outputs)
		f.Close()
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomains(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleDomains enumerates subdomains for multiple domains
// We keep enumerating subdomains for a given domain until we reach an error
func (r *Runner) EnumerateMultipleDomains(ctx context.Context, reader io.Reader, outputs []io.Writer) error {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain == "" {
			continue
		}

		var err error
		var file *os.File
		// If the user has specified an output file, use that output file instead
		// of creating a new output file for each domain. Else create a new file
		// for each domain in the directory.
		if r.options.OutputFile != "" {
			outputter := NewOutputter(r.options.JSON)
			file, err = outputter.createFile(r.options.OutputFile, true)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			err = r.EnumerateSingleDomain(ctx, domain, append(outputs, file))

			file.Close()
		} else if r.options.OutputDirectory != "" {
			outputFile := path.Join(r.options.OutputDirectory, domain)
			if r.options.JSON {
				outputFile += ".json"
			} else {
				outputFile += ".txt"
			}

			outputter := NewOutputter(r.options.JSON)
			file, err = outputter.createFile(outputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			err = r.EnumerateSingleDomain(ctx, domain, append(outputs, file))

			file.Close()
		} else {
			err = r.EnumerateSingleDomain(ctx, domain, outputs)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
