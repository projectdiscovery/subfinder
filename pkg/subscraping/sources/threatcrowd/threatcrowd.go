package threatcrowd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	timeTaken time.Duration
	errors    int
	results   int
}

// Run queries the ThreatCrowd API for the given domain and returns found subdomains.
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func(startTime time.Time) {
		defer func() {
			s.timeTaken = time.Since(startTime)
			close(results)
		}()

		url := fmt.Sprintf("http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
			}
		}()

		if resp.StatusCode != http.StatusOK {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
			s.errors++
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		var tcResponse threatCrowdResponse
		if err := json.Unmarshal(body, &tcResponse); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		for _, subdomain := range tcResponse.Subdomains {
			if subdomain != "" {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results++
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

// NeedsKey indicates if the source requires an API key.
func (s *Source) NeedsKey() bool {
	return false
}

// AddApiKeys is a no-op since ThreatCrowd does not require an API key.
func (s *Source) AddApiKeys(_ []string) {}

// Statistics returns usage statistics.
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
