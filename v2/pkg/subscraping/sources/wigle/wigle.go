package wigle

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	maxWiglePages   = 10
	maxResultsPerPage = 100
	wigleBaseURL    = "https://api.wigle.net/api/v2/network/search"
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

// WigleResponse represents the structure of the Wigle API response for a network search
type WigleResponse struct {
	Results []struct {
		SSID string `json:"ssid"`
		// Add other fields as needed based on the Wigle API response
	} `json:"results"`
}

// Run function returns information from Wigle related to the SSID
func (s *Source) Run(ctx context.Context, ssid string, session *subscraping.Session) <-chan subscraping.Result {
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
		url := fmt.Sprintf("%s?ssid=%s&page=1", wigleBaseURL, ssid)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Basic "+randomApiKey.token)

		resp, err := client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		defer resp.Body.Close()

		var wigleResponse WigleResponse
		err = json.NewDecoder(resp.Body).Decode(&wigleResponse)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		// Process the Wigle response and extract relevant information
		for _, result := range wigleResponse.Results {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.SSID, Value: result.SSID}
			s.results++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "wigle"
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
