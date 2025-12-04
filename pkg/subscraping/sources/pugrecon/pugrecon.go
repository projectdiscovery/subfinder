// Package pugrecon logic
package pugrecon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// pugreconResult stores a single result from the pugrecon API
type pugreconResult struct {
	Name string `json:"name"`
}

// pugreconAPIResponse stores the response from the pugrecon API
type pugreconAPIResponse struct {
	Results        []pugreconResult `json:"results"`
	QuotaRemaining int              `json:"quota_remaining"`
	Limited        bool             `json:"limited"`
	TotalResults   int              `json:"total_results"`
	Message        string           `json:"message"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		// Prepare POST request data
		postData := map[string]string{"domain_name": domain}
		bodyBytes, err := json.Marshal(postData)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("failed to marshal request body: %w", err)}
			s.errors++
			return
		}
		bodyReader := bytes.NewReader(bodyBytes)

		// Prepare headers
		headers := map[string]string{
			"Authorization": "Bearer " + randomApiKey,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		}

		apiURL := "https://pugrecon.com/api/v1/domains"
		resp, err := session.HTTPRequest(ctx, http.MethodPost, apiURL, "", headers, bodyReader, subscraping.BasicAuth{}) // Use HTTPRequest for full header control
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("failed to close response body: %w", err)}
				s.errors++
			}
		}()

		if resp.StatusCode != http.StatusOK {
			errorMsg := fmt.Sprintf("received status code %d", resp.StatusCode)
			// Attempt to read error message from body if possible
			var apiResp pugreconAPIResponse
			if json.NewDecoder(resp.Body).Decode(&apiResp) == nil && apiResp.Message != "" {
				errorMsg = fmt.Sprintf("%s: %s", errorMsg, apiResp.Message)
			}
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", errorMsg)}
			s.errors++
			return
		}

		var response pugreconAPIResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		for _, subdomain := range response.Results {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain.Name}:
				s.results++
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "pugrecon"
}

// IsDefault returns false as this is not a default source.
func (s *Source) IsDefault() bool {
	return false
}

// HasRecursiveSupport returns false as this source does not support recursive searches.
func (s *Source) HasRecursiveSupport() bool {
	return false
}

// NeedsKey returns true as this source requires an API key.
func (s *Source) NeedsKey() bool {
	return true
}

// AddApiKeys adds the API keys for the source.
func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

// Statistics returns the statistics for the source.
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
