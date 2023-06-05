package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/pkg/errors"

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

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	return runner, nil
}

// RunEnumeration wraps RunEnumerationWithCtx with an empty context
func (r *Runner) RunEnumeration() error {
	return r.RunEnumerationWithCtx(context.Background())
}

// RunEnumerationWithCtx runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, outputs)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f, outputs)
		f.Close()
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleDomains wraps EnumerateMultipleDomainsWithCtx with an empty context
func (r *Runner) EnumerateMultipleDomains(reader io.Reader, writers []io.Writer) error {
	return r.EnumerateMultipleDomainsWithCtx(context.Background(), reader, writers)
}

// EnumerateMultipleDomainsWithCtx enumerates subdomains for multiple domains
// We keep enumerating subdomains for a given domain until we reach an error
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	scanner := bufio.NewScanner(reader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
	for scanner.Scan() {
		domain, err := sanitize(scanner.Text())
		isIp := ip.MatchString(domain)
		if errors.Is(err, ErrEmptyInput) || (r.options.ExcludeIps && isIp) {
			continue
		}

		var file *os.File
		// If the user has specified an output file, use that output file instead
		// of creating a new output file for each domain. Else create a new file
		// for each domain in the directory.
		if r.options.OutputFile != "" {
			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(r.options.OutputFile, true)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			err = r.EnumerateSingleDomainWithCtx(ctx, domain, append(writers, file))

			file.Close()
		} else if r.options.OutputDirectory != "" {
			outputFile := path.Join(r.options.OutputDirectory, domain)
			if r.options.JSON {
				outputFile += ".json"
			} else {
				outputFile += ".txt"
			}

			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(outputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			err = r.EnumerateSingleDomainWithCtx(ctx, domain, append(writers, file))

			file.Close()
		} else {
			err = r.EnumerateSingleDomainWithCtx(ctx, domain, writers)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
