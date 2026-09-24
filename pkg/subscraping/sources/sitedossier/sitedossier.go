// Package sitedossier logic
package sitedossier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

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

		s.enumerate(ctx, session, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain), results, &stats)
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, session *subscraping.Session, baseURL string, results chan subscraping.Result, stats *subscraping.Statistics) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	stats.Requests++
	resp, err := session.SimpleGet(ctx, baseURL)
	isnotfound := resp != nil && resp.StatusCode == http.StatusNotFound
	if err != nil && !isnotfound {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		stats.Errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		stats.Errors++
		session.DiscardHTTPResponse(resp)
		return
	}
	session.DiscardHTTPResponse(resp)

	src := string(body)
	for _, subdomain := range session.Extractor.Extract(src) {
		select {
		case <-ctx.Done():
			return
		case results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Subdomain, Value: subdomain}:
			stats.Results++
		}
	}

	match := reNext.FindStringSubmatch(src)
	if len(match) > 0 {
		s.enumerate(ctx, session, fmt.Sprintf("http://www.sitedossier.com%s", match[1]), results, stats)
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "sitedossier"
}

func (s *Source) IsDefault() bool {
	return false
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
