// Package netlas logic
package netlas

import (
	"context"
	"io"
	"strings"

	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Item struct {
	Data struct {
		A           []string `json:"a,omitempty"`
		Txt         []string `json:"txt,omitempty"`
		LastUpdated string   `json:"last_updated,omitempty"`
		Timestamp   string   `json:"@timestamp,omitempty"`
		Ns          []string `json:"ns,omitempty"`
		Level       int      `json:"level,omitempty"`
		Zone        string   `json:"zone,omitempty"`
		Domain      string   `json:"domain,omitempty"`
		Cname       []string `json:"cname,omitempty"`
		Mx          []string `json:"mx,omitempty"`
	} `json:"data"`
}

type DomainsCountResponse struct {
	Count int `json:"count"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		// To get count of domains
		endpoint := "https://app.netlas.io/api/domains_count/"
		params := url.Values{}
		countQuery := fmt.Sprintf("domain:*.%s AND NOT domain:%s", domain, domain)
		params.Set("q", countQuery)
		countUrl := endpoint + "?" + params.Encode()

		// Pick an API key
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		resp1, err := session.HTTPRequest(ctx, http.MethodGet, countUrl, "", map[string]string{
			"accept":    "application/json",
			"X-API-Key": randomApiKey,
		}, nil, subscraping.BasicAuth{})

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		} else if resp1.StatusCode != 200 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request rate limited with status code %d", resp1.StatusCode)}
			s.errors++
			return
		}
		defer func() {
			if err := resp1.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
			}
		}()

		body, err := io.ReadAll(resp1.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("error reading ressponse body")}
			s.errors++
			return
		}

		// Parse the JSON response
		var domainsCount DomainsCountResponse
		err = json.Unmarshal(body, &domainsCount)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		// Make a single POST request to get all domains via download method

		apiUrl := "https://app.netlas.io/api/domains/download/"
		query := fmt.Sprintf("domain:*.%s AND NOT domain:%s", domain, domain)
		requestBody := map[string]any{
			"q":           query,
			"fields":      []string{"*"},
			"source_type": "include",
			"size":        domainsCount.Count,
		}
		jsonRequestBody, err := json.Marshal(requestBody)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("error marshaling request body")}
			s.errors++
			return
		}

		// Pick an API key
		randomApiKey = subscraping.PickRandom(s.apiKeys, s.Name())

		resp2, err := session.HTTPRequest(ctx, http.MethodPost, apiUrl, "", map[string]string{
			"accept":       "application/json",
			"X-API-Key":    randomApiKey,
			"Content-Type": "application/json"}, strings.NewReader(string(jsonRequestBody)), subscraping.BasicAuth{})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		defer func() {
			if err := resp2.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
			}
		}()
		body, err = io.ReadAll(resp2.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("error reading ressponse body")}
			s.errors++
			return
		}

		if resp2.StatusCode == 429 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request rate limited with status code %d", resp2.StatusCode)}
			s.errors++
			return
		}

		// Parse the response body and extract the domain values
		var data []Item
		err = json.Unmarshal(body, &data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		for _, item := range data {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: item.Data.Domain}:
				s.results++
			}
		}

	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "netlas"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
