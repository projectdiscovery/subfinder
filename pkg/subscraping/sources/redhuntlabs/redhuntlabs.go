// Package redhuntlabs logic
package redhuntlabs

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Response struct {
	Subdomains []string         `json:"subdomains"`
	Metadata   ResponseMetadata `json:"metadata"`
}

type ResponseMetadata struct {
	ResultCount int `json:"result_count"`
	PageSize    int `json:"page_size"`
	PageNumber  int `json:"page_number"`
}

type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()
	pageSize := 1000
	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		// Keys are "<base url>:<blobr key>"; the colon after the URL scheme makes three parts.
		keys := subscraping.NewKeyRing(slices.DeleteFunc(slices.Clone(apiKeys), func(key string) bool {
			return len(strings.Split(key, ":")) != 3
		}))
		if keys.Empty() {
			stats.Skipped = true
			return
		}

		// Honor an optional per-source result limit (0 = no limit) so a single
		// domain can't drain an API quota by paginating to the end.
		maxResults := session.MaxResults

		getPage := func(page int) (*http.Response, error) {
			return keys.Do(session, func(key string) (*http.Response, error) {
				parts := strings.Split(key, ":")
				stats.Requests++
				return session.Get(ctx, fmt.Sprintf("%s:%s?domain=%s&page=%d&page_size=%d", parts[0], parts[1], domain, page, pageSize), "",
					map[string]string{"X-BLOBR-KEY": parts[2], "User-Agent": "subfinder"})
			})
		}
		resp, err := getPage(1)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("encountered error: %v; note: if you get a 'limit has been reached' error, head over to https://devportal.redhuntlabs.com", err)}
			session.DiscardHTTPResponse(resp)
			stats.Errors++
			return
		}
		var response Response
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			stats.Errors++
			return
		}

		session.DiscardHTTPResponse(resp)
		emitResults := func() bool {
			for _, subdomain := range response.Subdomains {
				select {
				case <-ctx.Done():
					return false
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
				}
				if maxResults > 0 && stats.Results >= maxResults {
					return false
				}
			}
			return true
		}
		if !emitResults() {
			return
		}
		if response.Metadata.ResultCount > pageSize {
			totalPages := (response.Metadata.ResultCount + pageSize - 1) / pageSize
			for page := 2; page <= totalPages; page++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resp, err := getPage(page)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("encountered error: %v; note: if you get a 'limit has been reached' error, head over to https://devportal.redhuntlabs.com", err)}
					session.DiscardHTTPResponse(resp)
					stats.Errors++
					return
				}

				err = jsoniter.NewDecoder(resp.Body).Decode(&response)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					session.DiscardHTTPResponse(resp)
					stats.Errors++
					continue
				}

				session.DiscardHTTPResponse(resp)

				if !emitResults() {
					return
				}
			}
		}

	}()
	return results
}

func (s *Source) Name() string {
	return "redhuntlabs"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
