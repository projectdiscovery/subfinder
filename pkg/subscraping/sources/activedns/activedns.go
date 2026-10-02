// Package activedns logic
package activedns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const queryURL = "https://activedns.net/api/v1/query"

type alias struct {
	Name  string   `json:"name"`
	Chain []string `json:"chain"`
}

type record struct {
	Domain  string  `json:"domain"`
	Aliases []alias `json:"aliases"`
}

type response struct {
	Records    []record `json:"records"`
	HasMore    bool     `json:"has_more"`
	NextCursor int      `json:"next_cursor"`
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

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			stats.Skipped = true
			return
		}
		headers := map[string]string{
			"Authorization": "Bearer " + randomApiKey,
			"Accept":        "application/json",
			"User-Agent":    "subfinder",
		}

		// Records are per name/address pair, so the same name repeats across them.
		seen := make(map[string]struct{})
		maxResults := session.MaxResults
		cursor := 0
		for {
			params := url.Values{}
			params.Set("q", "*."+domain)
			if cursor > 0 {
				params.Set("cursor", strconv.Itoa(cursor))
			}

			stats.Requests++
			resp, err := session.Get(ctx, queryURL+"?"+params.Encode(), "", headers)
			// The token policy caps the cursor (1000 on community tokens) but the
			// last allowed page still reports has_more, so a later 400 ends paging.
			if err != nil && cursor > 0 && resp != nil && resp.StatusCode == http.StatusBadRequest {
				gologger.Debug().Msgf("%s: stopped paging at cursor %d: %s", s.Name(), cursor, err)
				session.DiscardHTTPResponse(resp)
				return
			}
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = json.NewDecoder(resp.Body).Decode(&data)
			session.DiscardHTTPResponse(resp)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				return
			}

			for _, rec := range data.Records {
				names := []string{rec.Domain}
				for _, a := range rec.Aliases {
					names = append(names, a.Name)
					names = append(names, a.Chain...)
				}
				for _, name := range names {
					for _, subdomain := range session.Extractor.Extract(name) {
						if _, ok := seen[subdomain]; ok {
							continue
						}
						seen[subdomain] = struct{}{}
						select {
						case <-ctx.Done():
							return
						case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
							stats.Results++
						}
						if maxResults > 0 && stats.Results >= maxResults {
							return
						}
					}
				}
			}

			if !data.HasMore {
				return
			}
			if data.NextCursor <= cursor {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("pagination cursor did not advance past %d", cursor)}
				stats.Errors++
				return
			}
			cursor = data.NextCursor
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "activedns"
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
