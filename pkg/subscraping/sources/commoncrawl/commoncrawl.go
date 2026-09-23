// Package commoncrawl logic
package commoncrawl

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	indexURL     = "https://index.commoncrawl.org/collinfo.json"
	maxYearsBack = 5
)

var year = time.Now().Year()

type indexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

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

		s.requests.Add(1)
		resp, err := session.SimpleGet(ctx, indexURL)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		var indexes []indexResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}
		session.DiscardHTTPResponse(resp)

		years := make([]string, 0)
		for i := range maxYearsBack {
			years = append(years, strconv.Itoa(year-i))
		}

		searchIndexes := make(map[string]string)
		for _, year := range years {
			for _, index := range indexes {
				if strings.Contains(index.ID, year) {
					if _, ok := searchIndexes[year]; !ok {
						searchIndexes[year] = index.APIURL
						break
					}
				}
			}
		}

		for _, apiURL := range searchIndexes {
			further := s.getSubdomains(ctx, apiURL, domain, session, results)
			if !further {
				break
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "commoncrawl"
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
		Requests:  int(s.requests.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
	}
}

func (s *Source) getSubdomains(ctx context.Context, searchURL, domain string, session *subscraping.Session, results chan subscraping.Result) bool {
	// Honor an optional per-source result limit (0 = no limit) so a single
	// domain can't trigger scanning every index to the end.
	maxResults := session.MaxResults
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			var headers = map[string]string{"Host": "index.commoncrawl.org"}
			s.requests.Add(1)
			resp, err := session.Get(ctx, fmt.Sprintf("%s?url=*.%s", searchURL, domain), "", headers)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return false
			}

			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					session.DiscardHTTPResponse(resp)
					return false
				default:
				}
				line := scanner.Text()
				if line == "" {
					continue
				}
				line, _ = url.QueryUnescape(line)
				for _, subdomain := range session.Extractor.Extract(line) {
					if subdomain != "" {
						subdomain = strings.ToLower(subdomain)
						subdomain = strings.TrimPrefix(subdomain, "25")
						subdomain = strings.TrimPrefix(subdomain, "2f")

						select {
						case <-ctx.Done():
							session.DiscardHTTPResponse(resp)
							return false
						case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
							s.results.Add(1)
						}
						if maxResults > 0 && s.results >= maxResults {
							session.DiscardHTTPResponse(resp)
							return false
						}
					}
				}
			}
			session.DiscardHTTPResponse(resp)
			return true
		}
	}
}
