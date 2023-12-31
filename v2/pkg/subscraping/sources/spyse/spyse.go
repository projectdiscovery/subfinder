package spyse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	maxSpysePages = 10
	maxResultsPerPage = 100
	spyseBaseURL = "https://api.spyse.com/v4/data/domain"
)

type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type apiKey struct {
	token string
}

// SpyseResponse represents the structure of the Spyse API response for a domain
type SpyseResponse struct {
	Results []struct {
		Domain string `json:"domain"`
		// Add other fields as needed based on the Spyse API response
	} `json:"results"`
}

// Run function returns information from Spyse related to the domain
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
		if randomApiKey.token == "" {
			s.skipped = true
			return
		}

		client := &http.Client{}
		url := fmt.Sprintf("%s/%s", spyseBaseURL, domain)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+randomApiKey.token)

		resp, err := client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		defer resp.Body.Close()

		var spyseResponse SpyseResponse
		err = json.NewDecoder(resp.Body).Decode(&spyseResponse)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		// Process the Spyse response and extract relevant information
		for _, result := range spyseResponse.Results {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: result.Domain}
			s.results++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "spyse"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, _ string) apiKey {
		return apiKey{k}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
