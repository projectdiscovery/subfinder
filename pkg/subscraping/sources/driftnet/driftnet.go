package driftnet

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
	// baseURL is the base URL for the driftnet API
	baseURL = "https://api.driftnet.io/v1/"

	// summaryLimit is the size of the summary limit that we send to the API
	summaryLimit = 10000
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    atomic.Int32
	results   atomic.Int32
	skipped   bool
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
	s.errors.Store(0)
	s.results.Store(0)

	// Waitgroup for subsources
	var wg sync.WaitGroup
	wg.Add(len(endpoints))

	// Map for dedupe between subsources
	dedupe := sync.Map{}

	// Close down results when all subsources finished
	go func(startTime time.Time) {
		wg.Wait()
		s.timeTaken = time.Since(startTime)
		close(results)
	}(time.Now())

	// Start up requests for all subsources
	for i := range endpoints {
		go s.runSubsource(ctx, domain, session, results, &wg, &dedupe, endpoints[i])
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

// NeedsKey indicates that we need an API key
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

// runSubsource queries a specific driftnet endpoint for subdomains and sends results to the channel
func (s *Source) runSubsource(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result, wg *sync.WaitGroup, dedupe *sync.Map, epConfig endpointConfig) {
	// Default headers
	headers := map[string]string{
		"accept": "application/json",
	}

	// Pick an API key
	randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
	if randomApiKey != "" {
		headers["authorization"] = "Bearer " + randomApiKey
	}

	// Request
	requestURL := fmt.Sprintf("%s%s?%s%s&summarize=host&summary_context=%s&summary_limit=%d", baseURL, epConfig.endpoint, epConfig.param, url.QueryEscape(domain), epConfig.context, summaryLimit)
	resp, err := session.Get(ctx, requestURL, "", headers)
	if err != nil {
		// HTTP 204 is not an error from the Driftnet API
		if resp == nil || resp.StatusCode != http.StatusNoContent {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
		}

		wg.Done()
		return
	}

	defer session.DiscardHTTPResponse(resp)

	// 204 means no results, any other response code is an error
	if resp.StatusCode != 200 {
		if resp.StatusCode != 204 {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("request failed with status %d", resp.StatusCode)}
			s.errors.Add(1)
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
		s.errors.Add(1)
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
				s.results.Add(1)
			}
		}
	}

	// Complete!
	wg.Done()
}
