// Package subdomaincenter logic
package subdomaincenter

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// pageSize is the number of names requested per authenticated page. The API
// accepts an explicit limit of up to 1,000,000, but smaller pages complete
// faster and are cheaper to retry individually.
const pageSize = 10000

// crawlKeySuffix opts an authenticated key into a live crawl, e.g.
// "subdomaincenter: [<key>:crawl]" in the provider config.
const crawlKeySuffix = "crawl"

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// page is one response from the cuttlefish engine.
type page struct {
	names      []string
	truncated  bool
	nextOffset int
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

		apiKey, crawl := parseAPIKey(subscraping.PickRandom(apiKeys, s.Name()))
		authenticated := apiKey != ""

		headers := map[string]string{"Accept": "application/json"}
		if authenticated {
			// The key travels in a header only: the API rejects it as a query
			// parameter so it cannot leak through proxy, browser or CDN logs.
			headers["X-API-Key"] = apiKey
		}

		for offset := 0; ; {
			// A live crawl is billed against its own quota and is cooled down
			// per domain, so it is only worth asking for once, on the first page.
			stats.Requests++
			current, err := fetchPage(ctx, session, domain, headers, authenticated, offset, crawl && authenticated && offset == 0)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				return
			}

			for _, name := range current.names {
				for _, subdomain := range session.Extractor.Extract(name) {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
						stats.Results++
						if session.MaxResults > 0 && stats.Results >= session.MaxResults {
							return
						}
					}
				}
			}

			// The anonymous tier ignores limit/offset and always answers with a
			// single capped sample, so there is nothing to page through.
			if !authenticated || !current.truncated || len(current.names) == 0 {
				return
			}
			offset = current.nextOffset
		}
	}()

	return results
}

// fetchPage returns one page of the cuttlefish result set for the domain.
func fetchPage(ctx context.Context, session *subscraping.Session, domain string, headers map[string]string, authenticated bool, offset int, crawl bool) (*page, error) {
	query := url.Values{}
	query.Set("domain", domain)
	query.Set("engine", "cuttlefish")
	if authenticated {
		query.Set("limit", strconv.Itoa(pageSize))
		query.Set("offset", strconv.Itoa(offset))
	}
	if crawl {
		query.Set("crawl", "true")
	}
	requestURL := "https://api.subdomain.center/?" + query.Encode()

	resp, err := session.Get(ctx, requestURL, "", headers)
	if err != nil {
		session.DiscardHTTPResponse(resp)
		return nil, err
	}
	defer session.DiscardHTTPResponse(resp)

	var names []string
	if err := json.NewDecoder(resp.Body).Decode(&names); err != nil {
		return nil, err
	}

	current := &page{
		names:     names,
		truncated: strings.EqualFold(resp.Header.Get("X-Truncated"), "true"),
		// Crawl-sourced names are added on top of the requested page, so the
		// response can hold more names than the page actually advanced by.
		nextOffset: offset + len(names),
	}
	if next, err := strconv.Atoi(resp.Header.Get("X-Next-Offset")); err == nil && next > offset {
		current.nextOffset = next
	}

	return current, nil
}

// parseAPIKey splits a configured key into the key itself and whether it opts
// into a live crawl.
func parseAPIKey(key string) (string, bool) {
	if apiKey, suffix, found := strings.Cut(key, ":"); found && strings.EqualFold(suffix, crawlKeySuffix) {
		return apiKey, true
	}
	return key, false
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "subdomaincenter"
}

func (s *Source) IsDefault() bool {
	return true
}

// HasRecursiveSupport indicates that we accept subdomains in addition to apex domains
func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.OptionalKey
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
