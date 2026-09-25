package driftnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	// baseURL is the base URL for the driftnet API
	baseURL = "https://api.driftnet.io/v1/"

	// summaryLimit is the size of the summary limit that we send to the API
	summaryLimit = 10000
)

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// runState is shared by the endpoints of one enumeration.
type runState struct {
	apiKeys  []string
	errors   atomic.Int32
	results  atomic.Int32
	requests atomic.Int32
}

// endpointConfig describes a driftnet endpoint that can used
type endpointConfig struct {
	// The API endpoint to be touched
	endpoint string

	// The API parameter used for query
	param string

	// The context that we should restrict to in results from this endpoint
	context string
}

// endpoints is a set of endpoint configs
var endpoints = []endpointConfig{
	{"ct/log", "field=host:", "cert-dns-name"},
	{"scan/protocols", "field=host:", "cert-dns-name"},
	{"scan/domains", "field=host:", "cert-dns-name"},
	{"domain/rdns", "host=", "dns-ptr"},
}

// summaryResponse is an API response
type summaryResponse struct {
	Summary struct {
		Other  int            `json:"other"`
		Values map[string]int `json:"values"`
	} `json:"summary"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	// Final results channel
	results := make(chan subscraping.Result)
	s.mu.Lock()
	run := &runState{apiKeys: s.apiKeys}
	s.mu.Unlock()

	// Waitgroup for subsources
	var wg sync.WaitGroup
	wg.Add(len(endpoints))

	// Map for dedupe between subsources
	dedupe := sync.Map{}

	// Close down results when all subsources finished
	go func(startTime time.Time) {
		wg.Wait()
		stats := subscraping.Statistics{
			TimeTaken: time.Since(startTime),
			Errors:    int(run.errors.Load()),
			Results:   int(run.results.Load()),
			Requests:  int(run.requests.Load()),
		}
		s.mu.Lock()
		s.stats = stats
		s.mu.Unlock()
		close(results)
	}(time.Now())

	// Start up requests for all subsources
	for i := range endpoints {
		go s.runSubsource(ctx, domain, session, results, &wg, &dedupe, endpoints[i], run)
	}

	// Return the results channel
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "driftnet"
}

// IsDefault indicates that this source should used as part of the default execution.
func (s *Source) IsDefault() bool {
	return true
}

// HasRecursiveSupport indicates that we accept subdomains in addition to apex domains
func (s *Source) HasRecursiveSupport() bool {
	return true
}

// KeyRequirement indicates that we need an API key
func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

// NeedsKey indicates that we need an API key
func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

// AddApiKeys copies keys for subsequent runs.
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

// runSubsource queries a specific driftnet endpoint for subdomains and sends results to the channel
func (s *Source) runSubsource(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result, wg *sync.WaitGroup, dedupe *sync.Map, epConfig endpointConfig, run *runState) {
	// Default headers
	headers := map[string]string{
		"accept": "application/json",
	}

	// Pick an API key
	randomApiKey := subscraping.PickRandom(run.apiKeys, s.Name())
	if randomApiKey != "" {
		headers["authorization"] = "Bearer " + randomApiKey
	}

	// Request
	requestURL := fmt.Sprintf("%s%s?%s%s&summarize=host&summary_context=%s&summary_limit=%d", baseURL, epConfig.endpoint, epConfig.param, url.QueryEscape(domain), epConfig.context, summaryLimit)
	run.requests.Add(1)
	resp, err := session.Get(ctx, requestURL, "", headers)
	if err != nil {
		// HTTP 204 is not an error from the Driftnet API
		if resp == nil || resp.StatusCode != http.StatusNoContent {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			run.errors.Add(1)
		}

		wg.Done()
		return
	}

	defer session.DiscardHTTPResponse(resp)

	// 204 means no results, any other response code is an error
	if resp.StatusCode != 200 {
		if resp.StatusCode != 204 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request failed with status %d", resp.StatusCode)}
			run.errors.Add(1)
		}

		wg.Done()
		return
	}

	// Parse and return results
	var summary summaryResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&summary)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		run.errors.Add(1)
		wg.Done()
		return
	}

	for subdomain := range summary.Summary.Values {
		select {
		case <-ctx.Done():
			wg.Done()
			return
		default:
		}
		if !strings.HasSuffix(subdomain, "."+domain) {
			continue
		}

		if _, present := dedupe.LoadOrStore(strings.ToLower(subdomain), true); !present {
			select {
			case <-ctx.Done():
				wg.Done()
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				run.results.Add(1)
			}
		}
	}

	// Complete!
	wg.Done()
}
