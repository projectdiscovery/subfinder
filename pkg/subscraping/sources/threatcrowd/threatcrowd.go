package threatcrowd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// threatCrowdResponse represents the JSON response from the ThreatCrowd API.
type threatCrowdResponse struct {
	ResponseCode string   `json:"response_code"`
	Subdomains   []string `json:"subdomains"`
	Undercount   string   `json:"undercount"`
}

// Source implements the subscraping.Source interface for ThreatCrowd.
type Source struct {
	timeTaken atomic.Int64 // nanoseconds; cast to time.Duration on read
	errors    atomic.Int32
	results   atomic.Int32
	requests  atomic.Int32
}

// Run queries the ThreatCrowd API for the given domain and returns found subdomains.
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors.Store(0)
	s.results.Store(0)
	s.requests.Store(0)

	go func(startTime time.Time) {
		defer func() {
			s.timeTaken.Store(int64(time.Since(startTime)))
			close(results)
		}()

		url := fmt.Sprintf("http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}

		s.requests.Add(1)
		resp, err := session.Client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}
		// This source issues a raw client.Do (bypassing the session's
		// httpRequestWrapper), so apply the response-body size cap explicitly
		// when configured (0 = unlimited).
		subscraping.LimitResponseBody(resp, session.MaxResponseBodySize)
		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
			s.errors.Add(1)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}

		var tcResponse threatCrowdResponse
		if err := json.Unmarshal(body, &tcResponse); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			return
		}

		for _, subdomain := range tcResponse.Subdomains {
			if subdomain != "" {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results.Add(1)
				}
			}
		}
	}(time.Now())

	return results
}

// Name returns the name of the source.
func (s *Source) Name() string {
	return "threatcrowd"
}

// IsDefault indicates whether this source is enabled by default.
func (s *Source) IsDefault() bool {
	return false
}

// HasRecursiveSupport indicates if the source supports recursive searches.
func (s *Source) HasRecursiveSupport() bool {
	return false
}

// KeyRequirement returns the API key requirement level for this source.
func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

// NeedsKey indicates if the source requires an API key.
func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

// AddApiKeys is a no-op since ThreatCrowd does not require an API key.
func (s *Source) AddApiKeys(_ []string) {}

// Statistics returns usage statistics.
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Requests:  int(s.requests.Load()),
	}
}
