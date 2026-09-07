// Package subdomaincenter logic
package subdomaincenter

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
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
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
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
	s.errors = 0
	s.results = 0
	s.requests = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		apiKey, crawl := parseAPIKey(subscraping.PickRandom(s.apiKeys, s.Name()))
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
			current, err := s.fetchPage(ctx, session, domain, headers, authenticated, offset, crawl && authenticated && offset == 0)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			for _, name := range current.names {
				for _, subdomain := range session.Extractor.Extract(name) {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
						s.results++
						if session.MaxResults > 0 && s.results >= session.MaxResults {
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
func (s *Source) fetchPage(ctx context.Context, session *subscraping.Session, domain string, headers map[string]string, authenticated bool, offset int, crawl bool) (*page, error) {
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

	s.requests++
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
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
		Requests:  s.requests,
	}
}
