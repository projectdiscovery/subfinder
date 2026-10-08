// Package virustotal logic
package virustotal

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Data []Object `json:"data"`
	Meta Meta     `json:"meta"`
}

type Object struct {
	Id string `json:"id"`
}

type Meta struct {
	Cursor string `json:"cursor"`
}

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		// Honor an optional per-source result limit to avoid unnecessary
		// pagination requests (e.g. to stay within API quotas). 0 = no limit.
		maxResults := session.MaxResults

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}
		var cursor = ""
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var url = fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)
			if cursor != "" {
				url = fmt.Sprintf("%s&cursor=%s", url, cursor)
			}
			stats.Requests++
			resp, err := session.Get(ctx, url, "", map[string]string{"x-apikey": randomApiKey})
			if err != nil {
				// The free tier grants 500 requests/day; once it is exhausted every
				// call returns HTTP 429. Surface an actionable message instead of the
				// generic "unexpected status code 429" so operators know to supply an
				// enterprise key or lower the scope (see #1718).
				if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
					err = fmt.Errorf("virustotal quota exhausted (HTTP 429); some subdomains for %s may be missing", domain)
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			// Close the body per iteration; deferring inside the loop would keep
			// every page's body (and its connection) open until the goroutine exits.
			if closeErr := resp.Body.Close(); closeErr != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: closeErr}
				stats.Errors++
			}
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				return
			}

			for _, subdomain := range data.Data {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain.Id}:
					stats.Results++
				}
				if maxResults > 0 && stats.Results >= maxResults {
					return
				}
			}
			cursor = data.Meta.Cursor
			if cursor == "" {
				break
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "virustotal"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

// AddApiKeys copies keys for subsequent runs.
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
