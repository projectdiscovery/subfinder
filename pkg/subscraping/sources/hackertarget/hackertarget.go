// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

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

		htSearchUrl := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		search := func(key string) (*http.Response, error) {
			searchURL := htSearchUrl
			if key != "" {
				searchURL = fmt.Sprintf("%s&apikey=%s", htSearchUrl, key)
			}
			stats.Requests++
			return session.SimpleGet(ctx, searchURL)
		}

		resp, err := subscraping.NewKeyRing(apiKeys).Do(session, search)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			stats.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
			}
		}()

		scanner := bufio.NewScanner(resp.Body)
		firstLine := true
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			if firstLine {
				firstLine = false
				if isErrorBody(line) {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: errors.New(line)}
					stats.Errors++
					return
				}
			}
			match := session.Extractor.Extract(line)
			for _, subdomain := range match {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					stats.Results++
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hackertarget"
}

func (s *Source) IsDefault() bool {
	return true
}

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

// isErrorBody reports whether the first line of a response is an API error.
// The API sends errors such as "error invalid key" and "API count exceeded"
// with HTTP 200, so the status code alone does not reveal them.
func isErrorBody(line string) bool {
	line = strings.ToLower(line)
	return strings.HasPrefix(line, "error") || strings.HasPrefix(line, "api count exceeded")
}
