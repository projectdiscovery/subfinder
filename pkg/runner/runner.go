package runner

import (
	"bufio"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/pkg/log"
	"github.com/projectdiscovery/subfinder/pkg/passive"
	"github.com/projectdiscovery/subfinder/pkg/resolve"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
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
		return r.EnumerateSingleDomain(r.options.Domain, r.options.Output)
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
	for scanner.Scan() {
		domain := scanner.Text()
		if domain == "" {
			continue
		}

		outputFile := path.Join(r.options.OutputDirectory, domain)
		err := r.EnumerateSingleDomain(domain, outputFile)
		if err != nil {
			return err
		}
	}
	return nil
}

// EnumerateSingleDomain performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomain(domain, output string) error {
	log.Infof("Enumerating subdomains for %s\n", domain)

	// Get the API keys for sources from the configuration
	// and also create the active resolving engine for the domain.
	keys := r.options.YAMLConfig.GetKeys()
	resolutionPool := r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
	err := resolutionPool.InitWildcards(domain)
	if err != nil {
		// Log the error but don't quit.
		log.Warningf("Could not get wildcards for domain %s: %s\n", domain, err)
	}

	// Max time for performing enumeration is 5 mins
	// Run the passive subdomain enumeration
	passiveResults := r.passiveAgent.EnumerateSubdomains(domain, keys, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute)

	wg := &sync.WaitGroup{}
	// Process the results in a separate goroutine
	go func() {
		// Create a unique map for filtering duplicate subdomains out
		uniqueMap := make(map[string]struct{})

		wg.Add(1)
		for result := range passiveResults {
			switch result.Type {
			case subscraping.Error:
				log.Warningf("Could not run source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				// Validate the subdomain found and remove wildcards from
				if !strings.HasSuffix(result.Value, "."+domain) {
					continue
				}
				subdomain := strings.ReplaceAll(strings.ToLower(result.Value), "*.", "")

				// Check if the subdomain is a duplicate. If not,
				// send the subdomain for resolution.
				if _, ok := uniqueMap[subdomain]; ok {
					continue
				}
				uniqueMap[subdomain] = struct{}{}

				// Log the verbose message about the found subdomain and send the
				// host for resolution to the resolution pool
				log.Verbosef("%s\n", result.Source, subdomain)

				resolutionPool.Tasks <- subdomain
			}
		}
		close(resolutionPool.Tasks)
		wg.Done()
	}()

	foundResults := make(map[string]string)
	// Process the results coming from the resolutions pool
	for result := range resolutionPool.Results {
		switch result.Type {
		case resolve.Error:
			log.Warningf("Could not resolve host: %s\n", result.Error)
		case resolve.Subdomain:
			// Add the found subdomain to a map.
			if _, ok := foundResults[result.Host]; !ok {
				foundResults[result.Host] = result.IP
			}
		}
	}
	wg.Wait()

	// Print all the found subdomains on the screen
	for result := range foundResults {
		log.Silentf("%s\n", result)
	}

	// In case the user has given an output file, write all the found
	// subdomains to the output file.
	if output != "" {
		// If the output format is json, append .json
		// else append .txt
		if r.options.OutputDirectory != "" {
			if r.options.JSON {
				output = output + ".json"
			} else {
				output = output + ".txt"
			}
		}

		file, err := os.Create(output)
		if err != nil {
			log.Errorf("Could not create file %s for %s: %s\n", output, domain, err)
			return err
		}

		// Write the output to the file depending upon user requirement
		if r.options.HostIP {
			err = WriteHostIPOutput(foundResults, file)
		} else if r.options.JSON {
			err = WriteJSONOutput(foundResults, file)
		} else {
			err = WriteHostOutput(foundResults, file)
		}
		if err != nil {
			log.Errorf("Could not write results to file %s for %s: %s\n", output, domain, err)
		}
		file.Close()
		return err
	}
	return nil
}
