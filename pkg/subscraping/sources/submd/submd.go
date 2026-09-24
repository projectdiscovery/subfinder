package submd

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

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
		resp, err := s.fetch(ctx, domain, session, apiKeys)
		if err != nil {
			s.trySendError(ctx, results, err, &stats)
			session.DiscardHTTPResponse(resp)
			return
		}
		defer session.DiscardHTTPResponse(resp)

		if resp.StatusCode != http.StatusOK {
			return
		}

		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); line != "" {
				for _, sub := range session.Extractor.Extract(line) {
					if !s.trySendResult(ctx, results, sub, &stats) {
						return
					}
				}
			}
		}
		if err := sc.Err(); err != nil {
			s.trySendError(ctx, results, err, &stats)
		}
	}()

	return results
}

// trySendResult emits a subdomain result, honoring ctx cancellation.
// Returns false if the context was cancelled and the caller should stop.
func (s *Source) trySendResult(ctx context.Context, ch chan<- subscraping.Result, value string, stats *subscraping.Statistics) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
		stats.Results++
		return true
	}
}

// trySendError emits an error result, honoring ctx cancellation.
func (s *Source) trySendError(ctx context.Context, ch chan<- subscraping.Result, err error, stats *subscraping.Statistics) {
	select {
	case <-ctx.Done():
	case ch <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
		stats.Errors++
	}
}

// fetch issues the API call, upgrades to Bearer auth when a key is available.
func (s *Source) fetch(ctx context.Context, domain string, session *subscraping.Session, apiKeys []string) (*http.Response, error) {
	endpoint := "https://api.sub.md/v1/search?apex=" + url.QueryEscape(domain)

	if len(apiKeys) > 0 {
		return session.Get(ctx, endpoint, "", map[string]string{
			"Authorization": "Bearer " + subscraping.PickRandom(apiKeys, s.Name()),
		})
	}
	return session.SimpleGet(ctx, endpoint)
}

func (s *Source) Name() string              { return "submd" }
func (s *Source) IsDefault() bool           { return true }
func (s *Source) HasRecursiveSupport() bool { return false }

func (s *Source) KeyRequirement() subscraping.KeyRequirement { return subscraping.OptionalKey }
func (s *Source) NeedsKey() bool                             { return s.KeyRequirement() == subscraping.RequiredKey }
func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
