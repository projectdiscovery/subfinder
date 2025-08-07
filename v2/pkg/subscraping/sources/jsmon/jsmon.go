// Package jsmon logic
package jsmon

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
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

		// Parse API key in format: baseUrl:apiKey:wkspId
		var baseUrl, authToken, wkspId string
		if len(s.apiKeys) > 0 {
			apiKeyString := s.apiKeys[0]

			// Find the last two colons to split properly
			lastColonIndex := strings.LastIndex(apiKeyString, ":")
			if lastColonIndex == -1 {
				fmt.Printf("[DEBUG] No colons found in API key\n")
				s.skipped = true
				return
			}

			secondLastColonIndex := strings.LastIndex(apiKeyString[:lastColonIndex], ":")
			if secondLastColonIndex == -1 {
				fmt.Printf("[DEBUG] Only one colon found in API key\n")
				s.skipped = true
				return
			}

			baseUrl = apiKeyString[:secondLastColonIndex]
			authToken = apiKeyString[secondLastColonIndex+1 : lastColonIndex]
			wkspId = apiKeyString[lastColonIndex+1:]

		}

		subfinderScanURL := fmt.Sprintf("%s/api/v2/subfinderScan2?wkspId=%s", baseUrl, wkspId)

		requestBody := fmt.Sprintf(`{"domain":"%s"}`, domain)

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

		var response subdomainsResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		session.DiscardHTTPResponse(resp)

		for _, subdomain := range response.Subdomains {
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
	return true
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
