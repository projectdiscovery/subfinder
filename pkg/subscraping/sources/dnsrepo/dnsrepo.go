package dnsrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type DnsRepoResponse []struct {
	Domain string `json:"domain"`
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		randomApiInfo := strings.Split(randomApiKey, ":")
		if len(randomApiInfo) != 2 {
			s.skipped = true
			return
		}

		token := randomApiInfo[0]
		apiKey := randomApiInfo[1]

		resp, err := session.Get(ctx, fmt.Sprintf("https://dnsarchive.net/api/?apikey=%s&search=%s", apiKey, domain), "", map[string]string{"X-API-Access": token})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		responseData, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		session.DiscardHTTPResponse(resp)
		var result DnsRepoResponse
		err = json.Unmarshal(responseData, &result)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}
		for _, sub := range result {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: strings.TrimSuffix(sub.Domain, ".")}:
				s.results++
			}
		}

	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "dnsrepo"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
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
	}
}
