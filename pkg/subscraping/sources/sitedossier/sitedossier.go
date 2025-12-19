// Package sitedossier logic
package sitedossier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		s.enumerate(ctx, session, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain), results)
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, session *subscraping.Session, baseURL string, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := session.SimpleGet(ctx, baseURL)
	isnotfound := resp != nil && resp.StatusCode == http.StatusNotFound
	if err != nil && !isnotfound {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}
	session.DiscardHTTPResponse(resp)

	src := string(body)
	for _, subdomain := range session.Extractor.Extract(src) {
		select {
		case <-ctx.Done():
			return
		case results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Subdomain, Value: subdomain}:
			s.results++
		}
	}

	match := reNext.FindStringSubmatch(src)
	if len(match) > 0 {
		s.enumerate(ctx, session, fmt.Sprintf("http://www.sitedossier.com%s", match[1]), results)
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "sitedossier"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
