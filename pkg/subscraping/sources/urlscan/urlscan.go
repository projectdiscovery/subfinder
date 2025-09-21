package urlscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	// baseURL is the base URL for the urlscan.io API
	baseURL = "https://urlscan.io/api/v1/"

	// pageSize is the number of results to request per page (max 100)
	pageSize = 100

	// maxResultsFree is a soft cap aligned to free-tier search cap (~1000). We stop after reaching it.
	maxResultsFree = 1000

	// maxPageRetries is the number of retries on rate-limit or transient errors per page
	maxPageRetries = 3

	// backoffBase is the initial backoff duration; we do simple exponential backoff on 429/5xx
	backoffBase = 2 * time.Second
)

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    atomic.Int32
	results   atomic.Int32
	skipped   bool
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "urlscan"
}

// IsDefault indicates that this source should be used as part of the default execution
func (s *Source) IsDefault() bool {
	return true
}

// HasRecursiveSupport indicates that we accept subdomains in addition to apex domains
func (s *Source) HasRecursiveSupport() bool {
	return true
}

// NeedsKey indicates whether this source strictly needs an API key
// urlscan.io search는 키 없이도 동작하지만(쿼터↓), 있으면 더 안정적이므로 false로 둡니다.
func (s *Source) NeedsKey() bool {
	return true
}

// AddApiKeys provides us with the API key(s)
func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

// Statistics returns statistics about the scraping process
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}

// searchResponse models the urlscan search response
type searchResponse struct {
	Total   int `json:"total"`
	Results []struct {
		Task struct {
			URL string `json:"url"`
		} `json:"task"`
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}

// Run queries urlscan.io Search API for subdomains and streams results
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	s.errors.Store(0)
	s.results.Store(0)
	s.skipped = false

	go func(start time.Time) {
		defer func() {
			s.timeTaken = time.Since(start)
			close(results)
		}()

		dedupe := sync.Map{}

		headers := map[string]string{
			"accept": "application/json",
		}
		if key := subscraping.PickRandom(s.apiKeys, s.Name()); key != "" {
			headers["API-Key"] = key
		}

		totalFetched := 0

		for {
			if totalFetched >= maxResultsFree {
				break
			}

			q := "domain:" + domain
			u := baseURL + "search/?" +
				"q=" + url.QueryEscape(q) +
				"&size=" + url.QueryEscape(fmt.Sprintf("%d", pageSize))

			var resp *http.Response
			var err error
			backoff := backoffBase

			for attempt := 0; attempt <= maxPageRetries; attempt++ {
				resp, err = session.Get(ctx, u, "", headers)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors.Add(1)
					break
				}

				if resp.StatusCode == http.StatusOK {
					break
				}

				session.DiscardHTTPResponse(resp)

				if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode < 600) {
					select {
					case <-time.After(backoff):
						backoff *= 2
						continue
					case <-ctx.Done():
						err = ctx.Err()
					}
				}

				err = fmt.Errorf("urlscan search returned status %d", resp.StatusCode)
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				break
			}

			if err != nil {
				break
			}

			var sr searchResponse
			dec := json.NewDecoder(resp.Body)
			if perr := dec.Decode(&sr); perr != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: perr}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				break
			}
			session.DiscardHTTPResponse(resp)

			if len(sr.Results) == 0 {
				break
			}

			for _, r := range sr.Results {
				host := strings.ToLower(strings.TrimSpace(r.Page.Domain))
				if host == "" && r.Task.URL != "" {
					if parsed, perr := url.Parse(r.Task.URL); perr == nil && parsed != nil {
						host = strings.ToLower(parsed.Hostname())
					}
				}

				if host == "" {
					continue
				}

				host = strings.TrimPrefix(host, "www.")

				if !strings.HasSuffix(host, "."+domain) {
					if host != domain {
						continue
					} else {
						continue
					}
				}

				if _, present := dedupe.LoadOrStore(host, struct{}{}); present {
					continue
				}

				results <- subscraping.Result{
					Source: s.Name(),
					Type:   subscraping.Subdomain,
					Value:  host,
				}
				s.results.Add(1)
				totalFetched++

				if totalFetched >= maxResultsFree {
					break
				}
			}

			break
		}
	}(time.Now())

	return results
}
