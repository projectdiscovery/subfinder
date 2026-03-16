package runner

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// EnumerateSingleDomain wraps EnumerateSingleDomainWithCtx with an empty context
func (r *Runner) EnumerateSingleDomain(domain string, writers []io.Writer) (map[string]map[string]struct{}, error) {
	return r.EnumerateSingleDomainWithCtx(context.Background(), domain, writers)
}

// EnumerateSingleDomainWithCtx performs subdomain enumeration against a single domain,
// applying global and per-source rate limits from the runner options.
func (r *Runner) EnumerateSingleDomainWithCtx(ctx context.Context, domain string, writers []io.Writer) (map[string]map[string]struct{}, error) {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(domain)
		if err != nil {
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", domain, err)
		}
	}

	now := time.Now()
	passiveResults := r.passiveAgent.EnumerateSubdomainsWithCtx(
		ctx, domain, r.options.Proxy, r.options.RateLimit, r.options.Timeout,
		time.Duration(r.options.MaxEnumerationTime)*time.Minute,
		passive.WithCustomRateLimit(r.rateLimit),
	)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	uniqueMap := make(map[string]resolve.HostEntry)
	sourceMap := make(map[string]map[string]struct{})
	skippedCounts := make(map[string]int)
	go func() {
		for result := range passiveResults {
			switch result.Type {
			case subscraping.Error:
				gologger.Warning().Msgf("Encountered an error with source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				subdomain := replacer.Replace(result.Value)
				isWildcard := strings.Contains(result.Value, "*."+subdomain)
				if !strings.HasSuffix(subdomain, "."+domain) {
					skippedCounts[result.Source]++
					continue
				}
				if matchSubdomain := r.filterAndMatchSubdomain(subdomain); matchSubdomain {
					if _, ok := uniqueMap[subdomain]; !ok {
						sourceMap[subdomain] = make(map[string]struct{})
					}
					if _, ok := sourceMap[subdomain][result.Source]; !ok {
						gologger.Verbose().Label(result.Source).Msg(subdomain)
					}
					sourceMap[subdomain][result.Source] = struct{}{}
					if _, ok := uniqueMap[subdomain]; ok {
						skippedCounts[result.Source]++
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
					if r.options.RemoveWildcard {
						resolutionPool.Tasks <- hostEntry
					}
				}
			}
		}
		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
					if r.options.ResultCallback != nil {
						r.options.ResultCallback(&resolve.HostEntry{Domain: domain, Host: result.Host, Source: result.Source, WildcardCertificate: result.WildcardCertificate})
					}
				}
			}
		}
		for host, result := range foundResults {
			if entry, ok := uniqueMap[host]; ok && entry.WildcardCertificate && !result.WildcardCertificate {
				result.WildcardCertificate = true
				foundResults[host] = result
			}
		}
	}
	wg.Wait()
	outputWriter := NewOutputWriter(r.options.JSON)
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

// parseRateLimitStr parses a rate limit string of the form "<n>/s" or "<n>/m".
// A missing or unrecognised unit suffix is treated as an error to avoid
// silently applying the wrong time window.
func parseRateLimitStr(s string) (uint, time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("empty rate limit specification")
	}
	if strings.HasSuffix(s, "/m") {
		n, err := parseUintVal(strings.TrimSuffix(s, "/m"))
		return n, time.Minute, err
	}
	if strings.HasSuffix(s, "/s") {
		n, err := parseUintVal(strings.TrimSuffix(s, "/s"))
		return n, time.Second, err
	}
	return 0, 0, fmt.Errorf("rate limit %q has no recognised unit suffix (/s or /m)", s)
}

// parseUintVal parses a non-negative integer string using strconv for strict validation.
func parseUintVal(s string) (uint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty value")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %w", s, err)
	}
	return uint(n), nil
}
