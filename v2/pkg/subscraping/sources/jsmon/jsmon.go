// Package jsmon logic
package jsmon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type subdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
	Status     string   `json:"status"`
	Message    string   `json:"message"`
}

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

		if len(s.apiKeys) == 0 {
			s.skipped = true
			return
		}

		// API keys structure: [baseUrl, authToken, workspaceId]
		var baseUrl, authToken, wkspId string
		if len(s.apiKeys) >= 1 {
			baseUrl = s.apiKeys[0]
		}
		if len(s.apiKeys) >= 2 {
			authToken = s.apiKeys[1]
		}
		if len(s.apiKeys) >= 3 {
			wkspId = s.apiKeys[2]
		}

		// fmt.Printf("[DEBUG] API Keys parsed - baseUrl: %s, authToken: %s, wkspId: %s\n", baseUrl, authToken, wkspId)
		// fmt.Printf("[DEBUG] Total API keys provided: %d\n", len(s.apiKeys))

		// Use the direct subfinderScan endpoint
		subfinderScanURL := fmt.Sprintf("%s/api/v2/subfinderScan?wkspId=%s", baseUrl, wkspId)

		// Prepare the request body with domain
		requestBody := fmt.Sprintf(`{"domain":"%s"}`, domain)

		// Prepare headers with Authorization
		headers := map[string]string{
			"X-Jsmon-Key":  authToken,
			"Content-Type": "application/json",
		}

		resp, err := session.Post(ctx, subfinderScanURL, "", headers, bytes.NewReader([]byte(requestBody)))
		if err != nil {
			// fmt.Printf("[DEBUG] Request error: %v\n", err)
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		// fmt.Printf("[DEBUG] Response status: %d\n", resp.StatusCode)

		if resp.StatusCode != 200 {
			// Read response body for error details
			body, _ := io.ReadAll(resp.Body)
			// fmt.Printf("[DEBUG] Error response body: %s\n", string(body))
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("subfinderScan API returned status %d: %s", resp.StatusCode, string(body))}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		// Parse the response as a direct array of subdomains
		var subdomains []string
		err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			// Read response body for debugging
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("[DEBUG] Response body: %s\n", string(body))
			fmt.Printf("[DEBUG] JSON decode error: %v\n", err)
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		fmt.Printf("[INF] Found %d subdomains\n", len(subdomains))

		session.DiscardHTTPResponse(resp)

		// Process subdomains
		for _, subdomain := range subdomains {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			s.results++
		}

	}()

	return results
}

func (s *Source) Name() string {
	return "jsmon"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return true
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
