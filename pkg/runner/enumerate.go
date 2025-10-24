package runner

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"

	"github.com/projectdiscovery/gologger"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const maxNumCount = 2

var replacer = strings.NewReplacer(
	"/", "",
	"•.", "",
	"•", "",
	"*.", "",
	"http://", "",
	"https://", "",
)

// EnumerateSingleDomain wraps EnumerateSingleDomainWithCtx with an empty context
func (r *Runner) EnumerateSingleDomain(domain string, writers []io.Writer) (map[string]map[string]struct{}, error) {
	return r.EnumerateSingleDomainWithCtx(context.Background(), domain, writers)
}

// EnumerateSingleDomainWithCtx performs subdomain enumeration against a single domain
func (r *Runner) EnumerateSingleDomainWithCtx(ctx context.Context, domain string, writers []io.Writer) (map[string]map[string]struct{}, error) {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Check if the user has asked to remove wildcards explicitly.
	// If yes, create the resolution pool and get the wildcards for the current domain
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(domain)
		if err != nil {
			// Log the error but don't quit.
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", domain, err)
		}
	}

	// Run the passive subdomain enumeration
	now := time.Now()
	passiveResults := r.passiveAgent.EnumerateSubdomainsWithCtx(ctx, domain, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute, passive.WithCustomRateLimit(r.rateLimit))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate subdomains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	skippedCounts := make(map[string]int)
	// Process the results in a separate goroutine
	go func() {
		for result := range passiveResults {
			switch result.Type {
			case subscraping.Error:
				gologger.Warning().Msgf("Encountered an error with source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				subdomain := replacer.Replace(result.Value)
				// check if this subdomain is actually a wildcard subdomain
				// that may have furthur subdomains associated with it
				isWildcard := strings.Contains(result.Value, "*."+subdomain)

				// Validate the subdomain found and remove wildcards from
				if !strings.HasSuffix(subdomain, "."+domain) {
					skippedCounts[result.Source]++
					continue
				}

				if matchSubdomain := r.filterAndMatchSubdomain(subdomain); matchSubdomain {
					if _, ok := uniqueMap[subdomain]; !ok {
						sourceMap[subdomain] = make(map[string]struct{})
					}

					// Log the verbose message about the found subdomain per source
					if _, ok := sourceMap[subdomain][result.Source]; !ok {
						gologger.Verbose().Label(result.Source).Msg(subdomain)
					}

					sourceMap[subdomain][result.Source] = struct{}{}

					// Check if the subdomain is a duplicate. If not,
					// send the subdomain for resolution.
					if _, ok := uniqueMap[subdomain]; ok {
						skippedCounts[result.Source]++
						// even if it is duplicate if it was not marked as wildcard before but this source says it is wildcard
						// then we should mark it as wildcard
						if !uniqueMap[subdomain].WildcardCertificate && isWildcard {
							val := uniqueMap[subdomain]
							val.WildcardCertificate = true
							uniqueMap[subdomain] = val
						}
						continue
					}

					hostEntry := resolve.HostEntry{Domain: domain, Host: subdomain, Source: result.Source, WildcardCertificate: isWildcard}
					if r.options.ResultCallback != nil && !r.options.RemoveWildcard {
						r.options.ResultCallback(&hostEntry)
					}

					uniqueMap[subdomain] = hostEntry
					// If the user asked to remove wildcard then send on the resolve
					// queue. Otherwise, if mode is not verbose print the results on
					// the screen as they are discovered.
					if r.options.RemoveWildcard {
						resolutionPool.Tasks <- hostEntry
					}
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
	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		// Process the results coming from the resolutions pool
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				// Add the found subdomain to a map.
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
					if r.options.ResultCallback != nil {
						r.options.ResultCallback(&resolve.HostEntry{Domain: domain, Host: result.Host, Source: result.Source, WildcardCertificate: result.WildcardCertificate})
					}
				}
			}
		}

		// Merge wildcard certificate information from uniqueMap into foundResults
		// This handles cases where a later source marked a subdomain as wildcard
		// after it was already sent to the resolution pool
		for host, result := range foundResults {
			if entry, ok := uniqueMap[host]; ok && entry.WildcardCertificate && !result.WildcardCertificate {
				result.WildcardCertificate = true
				foundResults[host] = result
			}
		}
	}
	wg.Wait()
	outputWriter := NewOutputWriter(r.options.JSON)
	// Now output all results in output writers
	var err error
	for _, writer := range writers {
		if r.options.HostIP {
			err = outputWriter.WriteHostIP(domain, foundResults, writer)
		} else {
			if r.options.RemoveWildcard {
				err = outputWriter.WriteHostNoWildcard(domain, foundResults, writer)
			} else {
				if r.options.CaptureSources {
					err = outputWriter.WriteSourceHost(domain, sourceMap, writer)
				} else {
					err = outputWriter.WriteHost(domain, uniqueMap, writer)
				}
			}
		}
		if err != nil {
			gologger.Error().Msgf("Could not write results for %s: %s\n", domain, err)
			return nil, err
		}
	}

	// Show found subdomain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	var numberOfSubDomains int
	if r.options.RemoveWildcard {
		numberOfSubDomains = len(foundResults)
	} else {
		numberOfSubDomains = len(uniqueMap)
	}

	gologger.Info().Msgf("Found %d subdomains for %s in %s\n", numberOfSubDomains, domain, duration)

	if r.options.Statistics {
		gologger.Info().Msgf("Printing source statistics for %s", domain)
		statistics := r.passiveAgent.GetStatistics()
		// This is a hack to remove the skipped count from the statistics
		// as we don't want to show it in the statistics.
		// TODO: Design a better way to do this.
		for source, count := range skippedCounts {
			if stat, ok := statistics[source]; ok {
				stat.Results -= count
				statistics[source] = stat
			}
		}
		printStatistics(statistics)
	}

	return sourceMap, nil
}

func (r *Runner) filterAndMatchSubdomain(subdomain string) bool {
	if r.options.filterRegexes != nil {
		for _, filter := range r.options.filterRegexes {
			if m := filter.MatchString(subdomain); m {
				return false
			}
		}
	}
	if r.options.matchRegexes != nil {
		for _, match := range r.options.matchRegexes {
			if m := match.MatchString(subdomain); m {
				return true
			}
		}
		return false
	}
	return true
}
