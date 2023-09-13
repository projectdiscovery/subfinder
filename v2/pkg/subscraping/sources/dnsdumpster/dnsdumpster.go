// Package dnsdumpster logic
package dnsdumpster

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// CSRFSubMatchLength CSRF regex submatch length
const CSRFSubMatchLength = 2

var re = regexp.MustCompile("<input type=\"hidden\" name=\"csrfmiddlewaretoken\" value=\"(.*)\">")

// getCSRFToken gets the CSRF Token from the page
func getCSRFToken(page string) string {
	if subs := re.FindStringSubmatch(page); len(subs) == CSRFSubMatchLength {
		return strings.TrimSpace(subs[1])
	}
	return ""
}

// postForm posts a form for a domain and returns the response
func postForm(ctx context.Context, session *subscraping.Session, token, domain string) (string, error) {
	params := url.Values{
		"csrfmiddlewaretoken": {token},
		"targetip":            {domain},
		"user":                {"free"},
	}

	resp, err := session.HTTPRequest(
		ctx,
		"POST",
		"https://dnsdumpster.com/",
		fmt.Sprintf("csrftoken=%s; Domain=dnsdumpster.com", token),
		map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer":      "https://dnsdumpster.com",
			"X-CSRF-Token": token,
		},
		strings.NewReader(params.Encode()),
		subscraping.BasicAuth{},
	)

	if err != nil {
		session.DiscardHTTPResponse(resp)
		return "", err
	}

	// Now, grab the entire page
	in, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in), err
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

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		resp, err := session.SimpleGet(ctx, "https://dnsdumpster.com/")
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		csrfToken := getCSRFToken(string(body))
		data, err := postForm(ctx, session, csrfToken, domain)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		for _, subdomain := range session.Extractor.Extract(data) {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			s.results++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "dnsdumpster"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
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
