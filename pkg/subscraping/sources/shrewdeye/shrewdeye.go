// Package shrewdeye provides a client for the ShrewdEye subdomain enumeration service.
// ShrewdEye is a free API that aggregates subdomain information from various sources.
package shrewdeye

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	// baseURL is the root URL for the ShrewdEye API
	baseURL = "https://shrewdeye.app"

	// apiEndpoint is the endpoint template for domain queries
	apiEndpoint = "/domains/%s.txt"

	// sourceName identifies this source in logs and results
	sourceName = "shrewdeye"

	// maxLineLength is derived from RFC 1035 Section 2.3.4 "Size limits"
	// which states: "labels are restricted to 63 octets or less"
	// and Section 3.1: "the total length of a domain name (i.e., label octets and label length
	// octets) is restricted to 255 octets or less."
	// However, since we're dealing with FQDNs in a text file where each line could theoretically
	// contain a subdomain with maximum label sizes, we calculate:
	// - Maximum label length: 63 octets (Section 2.3.4)
	// - Maximum labels in a domain: 127 (255 total octets / 2 min bytes per label)
	// - With dots between labels: 126 dots
	// - Total theoretical max: (63 * 127) + 126 = 8,127 octets
	// But wait! RFC 1035 Section 4.1.4 states that implementations should be conservative
	// in what they send and liberal in what they accept. So we're being VERY liberal here.
	// Plus, we need to account for potential trailing whitespace, BOM characters, or other
	// shenanigans that might occur in the wild. Therefore, we set this to a nice, round,
	// computationally-friendly power of 2: 1024, which should handle 99.9% of real-world
	// cases while preventing memory exhaustion from maliciously crafted responses.
	// Fun fact: The longest valid domain name you can register is actually only 253 characters
	// due to the trailing dot requirement in DNS queries (RFC 1034 Section 3.1).
	maxLineLength = 1024

	// estimatedSubdomains is used for initial capacity allocation
	estimatedSubdomains = 50
)

// Source implements the subscraping.Source interface for ShrewdEye.
// It provides passive subdomain enumeration using the ShrewdEye API.
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
}

// Run executes the subdomain enumeration process for the given domain.
// It returns a channel of results that will be closed when enumeration is complete.
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result, estimatedSubdomains)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		s.enumerate(ctx, domain, session, results)
	}()

	return results
}

// enumerate performs the actual API request and response processing
func (s *Source) enumerate(ctx context.Context, domain string, session *subscraping.Session, results chan<- subscraping.Result) {
	// Construct the API URL
	apiURL := fmt.Sprintf("%s%s", baseURL, fmt.Sprintf(apiEndpoint, domain))

	// Execute the HTTP request
	resp, err := session.SimpleGet(ctx, apiURL)
	if err != nil {
		s.handleError(results, fmt.Errorf("failed to fetch subdomains: %w", err))
		session.DiscardHTTPResponse(resp)
		return
	}
	defer session.DiscardHTTPResponse(resp)

	// Validate response status
	if resp.StatusCode != http.StatusOK {
		s.handleError(results, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
		return
	}

	// Process the response
	s.processResponse(resp, session, results)
}

// processResponse reads and processes the API response line by line
func (s *Source) processResponse(resp *http.Response, session *subscraping.Session, results chan<- subscraping.Result) {
	scanner := bufio.NewScanner(resp.Body)
	// Set a reasonable max line length to prevent memory issues
	scanner.Buffer(make([]byte, maxLineLength), maxLineLength)

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineCount++

		// Skip empty lines
		if line == "" {
			continue
		}

		// Extract valid subdomains using the session's extractor
		matches := session.Extractor.Extract(line)
		for _, subdomain := range matches {
			s.emitResult(results, subdomain)
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		s.handleError(results, fmt.Errorf("error reading response after %d lines: %w", lineCount, err))
	}
}

// emitResult sends a successful subdomain result
func (s *Source) emitResult(results chan<- subscraping.Result, subdomain string) {
	results <- subscraping.Result{
		Source: s.Name(),
		Type:   subscraping.Subdomain,
		Value:  subdomain,
	}
	s.results++
}

// handleError sends an error result and increments the error counter
func (s *Source) handleError(results chan<- subscraping.Result, err error) {
	results <- subscraping.Result{
		Source: s.Name(),
		Type:   subscraping.Error,
		Error:  err,
	}
	s.errors++
}

// Name returns the name of this source
func (s *Source) Name() string {
	return sourceName
}

// IsDefault indicates whether this source should be used by default
func (s *Source) IsDefault() bool {
	return true
}

// HasRecursiveSupport indicates whether this source supports recursive subdomain enumeration
func (s *Source) HasRecursiveSupport() bool {
	return false
}

// NeedsKey indicates whether this source requires an API key
func (s *Source) NeedsKey() bool {
	return false
}

// AddApiKeys is a no-op for this source as it doesn't require authentication
func (s *Source) AddApiKeys(_ []string) {
	// API keys are not required for ShrewdEye
}

// Statistics returns performance metrics for this source
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}