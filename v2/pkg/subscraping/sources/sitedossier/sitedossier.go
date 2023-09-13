// Package sitedossier logic
package sitedossier

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

type agent struct {
	results chan subscraping.Result
	errors  int
	session *subscraping.Session
}

func (a *agent) enumerate(ctx context.Context, baseURL string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.session.SimpleGet(ctx, baseURL)
	isnotfound := resp != nil && resp.StatusCode == http.StatusNotFound
	if err != nil && !isnotfound {
		a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		a.errors++
		a.session.DiscardHTTPResponse(resp)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		a.errors++
		resp.Body.Close()
		return
	}
	resp.Body.Close()

	src := string(body)
	for _, match := range a.session.Extractor.Extract(src) {
		a.results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Subdomain, Value: match}
	}

	match1 := reNext.FindStringSubmatch(src)
	time.Sleep(time.Duration((3 + rand.Intn(SleepRandIntn))) * time.Second)

	if len(match1) > 0 {
		a.enumerate(ctx, "http://www.sitedossier.com"+match1[1])
	}
}

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

	a := agent{
		session: session,
		results: results,
	}

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(a.results)
		}(time.Now())

		a.enumerate(ctx, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain))
		s.errors = a.errors
		s.results = len(a.results)
	}()

	return a.results
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
