// Package rapiddns is a RapidDNS Scraping Engine in Golang
package rapiddns

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

var pagePattern = regexp.MustCompile(`class="page-link" href="/subdomain/[^"]+\?page=(\d+)">`)

// Source is the passive scraping agent
type Source struct {
	timeTaken atomic.Int64 // nanoseconds; cast to time.Duration on read
	errors    atomic.Int32
	results   atomic.Int32
	requests  atomic.Int32
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors.Store(0)
	s.results.Store(0)
	s.requests.Store(0)

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken.Store(int64(time.Since(startTime)))
			close(results)
		}(time.Now())

		page := 1
		maxPages := 1
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.requests.Add(1)
			resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://rapiddns.io/subdomain/%s?page=%d&full=1", domain, page))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			src := string(body)
			for _, subdomain := range session.Extractor.Extract(src) {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results.Add(1)
				}
			}

			if maxPages == 1 {
				matches := pagePattern.FindAllStringSubmatch(src, -1)
				if len(matches) > 0 {
					lastMatch := matches[len(matches)-1]
					if len(lastMatch) > 1 {
						maxPages, _ = strconv.Atoi(lastMatch[1])
					}
				}
			}

			if page >= maxPages {
				break
			}
			page++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "rapiddns"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Requests:  int(s.requests.Load()),
	}
}
