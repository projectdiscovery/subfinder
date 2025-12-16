// Package merklemap logic
package merklemap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

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
		// Pick an API key, skip if no key is found
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		// Default headers
		headers := map[string]string{
			"accept": "application/json",
			// Set a user agent to prevent random one from pkg/subscraping/agent.go, it triggers the cloudflare protection of the api
			"User-Agent":    "subfinder",
			"Authorization": "Bearer " + randomApiKey,
		}

		// Fetch all pages with pagination
		// https://www.merklemap.com/documentation/search
		s.fetchAllPages(ctx, domain, headers, session, results)
	}()
	return results
}

// fetchAllPages fetches all pages of results using pagination
func (s *Source) fetchAllPages(ctx context.Context, domain string, headers map[string]string, session *subscraping.Session, results chan subscraping.Result) {
	baseURL := "https://api.merklemap.com/v1/search?query=" + url.QueryEscape("*."+domain)
	totalCount := math.MaxInt
	processedResults := 0

	// Iterate through all pages
	for page := 0; processedResults < totalCount; page++ {
		pageResp, err := s.fetchPage(ctx, baseURL, page, headers, session)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		if page == 0 {
			totalCount = pageResp.Count
		}

		// Stop if this page returned no results
		if len(pageResp.Results) == 0 {
			break
		}

		for _, result := range pageResp.Results {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Subdomain, Value: result.Hostname,
			}
			s.results++
			processedResults++
		}

	}
}

// fetchPage fetches a single page of results
func (s *Source) fetchPage(ctx context.Context, baseURL string, page int, headers map[string]string, session *subscraping.Session) (*response, error) {
	url := baseURL + "&page=" + strconv.Itoa(page)

	resp, err := session.Get(ctx, url, "", headers)
	if err != nil {
		return nil, err
	}
	defer session.DiscardHTTPResponse(resp)

	if resp.StatusCode != 200 {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var pageResponse response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(respBody))
	if err := decoder.Decode(&pageResponse); err != nil {
		return nil, err
	}

	return &pageResponse, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "merklemap"
}

func (s *Source) IsDefault() bool {
	return false
}

// HasRecursiveSupport indicates that we accept subdomains in addition to apex domains
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

type response struct {
	Count   int `json:"count"`
	Results []struct {
		Hostname          string `json:"hostname"`
		SubjectCommonName string `json:"subject_common_name"`
		FirstSeen         string `json:"first_seen"`
	} `json:"results"`
}
