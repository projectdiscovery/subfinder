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
	baseURL        = "https://urlscan.io/api/v1/"
	pageSize       = 100
	maxResultsFree = 1000

	maxPageRetries = 3
	backoffBase    = 2 * time.Second
)

// Source is the passive scraping agent for urlscan.io
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    atomic.Int32
	results   atomic.Int32
	skipped   bool
}

func (s *Source) Name() string { return "urlscan" }

func (s *Source) IsDefault() bool { return true }

func (s *Source) HasRecursiveSupport() bool { return true }

func (s *Source) NeedsKey() bool { return true }

func (s *Source) AddApiKeys(keys []string) { s.apiKeys = keys }

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}

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

		headers := map[string]string{"accept": "application/json"}
		if key := subscraping.PickRandom(s.apiKeys, s.Name()); key != "" {
			headers["API-Key"] = key
		}

		totalFetched := 0

		for totalFetched < maxResultsFree {
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
						results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: ctx.Err()}
						s.errors.Add(1)
						return
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
					continue
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
