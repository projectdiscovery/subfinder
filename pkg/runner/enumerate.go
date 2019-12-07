package runner

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/pkg/log"
	"github.com/projectdiscovery/subfinder/pkg/resolve"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// EnumerateSingleDomain performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomain(domain, output string) error {
	log.Infof("Enumerating subdomains for %s\n", domain)

	// Get the API keys for sources from the configuration
	// and also create the active resolving engine for the domain.
	keys := r.options.YAMLConfig.GetKeys()

	// Check if the user has asked to remove wildcards explicitly.
	// If yes, create the resolution pool and get the wildcards for the current domain
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(domain)
		if err != nil {
			// Log the error but don't quit.
			log.Warningf("Could not get wildcards for domain %s: %s\n", domain, err)
		}
	}

	// Run the passive subdomain enumeration
	passiveResults := r.passiveAgent.EnumerateSubdomains(domain, keys, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate subdomains out
	uniqueMap := make(map[string]struct{})
	// Process the results in a separate goroutine
	go func() {
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

				// If the user asked to remove wildcard then send on the resolve
				// queue. Otherwise, if mode is not verbose print the results on
				// the screen as they are discovered.
				if r.options.RemoveWildcard {
					resolutionPool.Tasks <- subdomain
				}

				if !r.options.Verbose {
					log.Silentf("%s\n", subdomain)
				}
			}
		}
		// Close the task channel only if wildcards are asked to be removed
		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	// If the user asked to remove wildcards, listen from the results
	// queue and write to the map. At the end, print the found results to the screen
	foundResults := make(map[string]string)
	if r.options.RemoveWildcard {
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
	}
	wg.Wait()

	// If verbose mode was used, then now print all the
	// found subdomains on the screen together.
	if r.options.Verbose {
		for result := range foundResults {
			log.Silentf("%s\n", result)
		}
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
			err = WriteHostOutput(uniqueMap, file)
		}
		if err != nil {
			log.Errorf("Could not write results to file %s for %s: %s\n", output, domain, err)
		}
		file.Close()
		return err
	}
	return nil
}
