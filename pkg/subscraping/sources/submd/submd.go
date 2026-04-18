package submd

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		s.requests++
		resp, err := s.fetch(ctx, domain, session)
		if err != nil {
			s.trySendError(ctx, results, err)
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
					if !s.trySendResult(ctx, results, sub) {
						return
					}
				}
			}
		}
		if err := sc.Err(); err != nil {
			s.trySendError(ctx, results, err)
		}
	}()

	return results
}

// trySendResult emits a subdomain result, honoring ctx cancellation.
// Returns false if the context was cancelled and the caller should stop.
func (s *Source) trySendResult(ctx context.Context, ch chan<- subscraping.Result, value string) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
		s.results++
		return true
	}
}

// trySendError emits an error result, honoring ctx cancellation.
func (s *Source) trySendError(ctx context.Context, ch chan<- subscraping.Result, err error) {
	select {
	case <-ctx.Done():
	case ch <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
		s.errors++
	}
}

// fetch issues the API call, upgrades to Bearer auth when a key is available.
func (s *Source) fetch(ctx context.Context, domain string, session *subscraping.Session) (*http.Response, error) {
	endpoint := "https://api.sub.md/v1/search?apex=" + url.QueryEscape(domain)

	if len(s.apiKeys) > 0 {
		return session.Get(ctx, endpoint, "", map[string]string{
			"Authorization": "Bearer " + subscraping.PickRandom(s.apiKeys, s.Name()),
		})
	}
	return session.SimpleGet(ctx, endpoint)
}

func (s *Source) Name() string              { return "submd" }
func (s *Source) IsDefault() bool           { return true }
func (s *Source) HasRecursiveSupport() bool { return false }

func (s *Source) KeyRequirement() subscraping.KeyRequirement { return subscraping.OptionalKey }
func (s *Source) NeedsKey() bool                             { return s.KeyRequirement() == subscraping.RequiredKey }
func (s *Source) AddApiKeys(keys []string)                   { s.apiKeys = keys }

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
	}
}
