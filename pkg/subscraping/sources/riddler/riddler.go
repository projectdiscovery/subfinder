// Package riddler logic
package riddler

import (
	"bufio"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	mu    sync.Mutex
	stats subscraping.Statistics
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		stats.Requests++
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://riddler.io/search?q=pld:%s&view_type=data_table", domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				session.DiscardHTTPResponse(resp)
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			for _, subdomain := range session.Extractor.Extract(line) {
				select {
				case <-ctx.Done():
					session.DiscardHTTPResponse(resp)
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
				}
			}
		}
		session.DiscardHTTPResponse(resp)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "riddler"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
