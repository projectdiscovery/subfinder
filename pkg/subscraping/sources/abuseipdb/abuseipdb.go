// Package abuseipdb logic
package abuseipdb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/utils/dns/wildcard"
)

// The whois page answers 403 without a session cookie; an empty value passes.
const sessionCookie = "abuseipdb_session="

// EPP status codes such as clientTransferProhibited use the same bare <li>
// markup, so match only after this heading to keep them out of the results.
const subdomainsHeading = "<h4>Subdomains</h4>"

var reSubdomain = regexp.MustCompile(`<li>([^<]+)</li>`)

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		// Whois answers for the registrable domain whatever host it is given,
		// so the labels it returns belong to that root rather than to domain.
		// Appending them to domain instead would invent names such as
		// www.app.example.com. The runner drops whatever falls out of scope.
		root, ok := wildcard.RegistrableRoot(domain)
		if !ok {
			return
		}

		s.requests++
		resp, err := session.Get(ctx, fmt.Sprintf("https://www.abuseipdb.com/whois/%s", root), sessionCookie, nil)
		if err != nil {
			s.sendError(ctx, results, err)
			session.DiscardHTTPResponse(resp)
			return
		}

		if resp.StatusCode != http.StatusOK {
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.sendError(ctx, results, err)
			// DiscardHTTPResponse gives up without closing when the drain
			// fails, which it will after a read error, so close it here.
			_ = resp.Body.Close()
			return
		}

		session.DiscardHTTPResponse(resp)

		_, subdomainsSection, found := strings.Cut(string(body), subdomainsHeading)
		if !found {
			return
		}

		for _, match := range reSubdomain.FindAllStringSubmatch(subdomainsSection, -1) {
			label := strings.TrimSpace(match[1])
			if label == "" {
				continue
			}
			subdomain := fmt.Sprintf("%s.%s", label, root)

			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				s.results++
			}
		}
	}()

	return results
}

// sendError matches the subdomain path: results is unbuffered, so a consumer
// that stopped reading after cancellation would otherwise block the send.
func (s *Source) sendError(ctx context.Context, results chan<- subscraping.Result, err error) {
	select {
	case <-ctx.Done():
	case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
		s.errors++
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "abuseipdb"
}

func (s *Source) IsDefault() bool {
	return true
}

// Off because every query resolves to the registrable domain, so feeding a
// discovered subdomain back in returns the same list a second time.
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
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
	}
}
