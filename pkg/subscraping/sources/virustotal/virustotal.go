// Package virustotal logic
package virustotal

import (
	"context"
	"fmt"
	"net/http"
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
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
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

		// Honor an optional per-source result limit to avoid unnecessary
		// pagination requests (e.g. to stay within API quotas). 0 = no limit.
		maxResults := session.MaxResults

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
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
			s.requests++
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
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var data response
			err = jsoniter.NewDecoder(resp.Body).Decode(&data)
			// Close the body per iteration; deferring inside the loop would keep
			// every page's body (and its connection) open until the goroutine exits.
			if closeErr := resp.Body.Close(); closeErr != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: closeErr}
				s.errors++
			}
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			for _, subdomain := range data.Data {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain.Id}:
					s.results++
				}
				if maxResults > 0 && s.results >= maxResults {
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

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
