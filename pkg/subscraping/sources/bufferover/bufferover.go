// Package bufferover is a bufferover Scraping Engine in Golang
package bufferover

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Meta struct {
		Errors []string `json:"Errors"`
	} `json:"Meta"`
	FDNSA   []string `json:"FDNS_A"`
	RDNS    []string `json:"RDNS"`
	Results []string `json:"Results"`
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

		s.getData(ctx, fmt.Sprintf("https://tls.bufferover.run/dns?q=.%s", domain), randomApiKey, session, results, &stats)
	}()

	return results
}

func (s *Source) getData(ctx context.Context, sourceURL string, apiKey string, session *subscraping.Session, results chan subscraping.Result, stats *subscraping.Statistics) {
	stats.Requests++
	resp, err := session.Get(ctx, sourceURL, "", map[string]string{"x-api-key": apiKey})

	if err != nil && resp == nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		stats.Errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	var bufforesponse response
	err = jsoniter.NewDecoder(resp.Body).Decode(&bufforesponse)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		stats.Errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	session.DiscardHTTPResponse(resp)

	metaErrors := bufforesponse.Meta.Errors

	if len(metaErrors) > 0 {
		results <- subscraping.Result{
			Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", strings.Join(metaErrors, ", ")),
		}
		stats.Errors++
		return
	}

	var subdomains []string

	if len(bufforesponse.FDNSA) > 0 {
		subdomains = bufforesponse.FDNSA
		subdomains = append(subdomains, bufforesponse.RDNS...)
	} else if len(bufforesponse.Results) > 0 {
		subdomains = bufforesponse.Results
	}

	for _, subdomain := range subdomains {
		for _, value := range session.Extractor.Extract(subdomain) {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
				stats.Results++
			}
		}
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "bufferover"
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
