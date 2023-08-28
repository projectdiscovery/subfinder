// Package redhuntlabs logic
package redhuntlabs

import (
	"context"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Response struct {
	Subdomains []string `json:"subdomains"`
}

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
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

		randomCred := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomCred == "" || !strings.Contains(randomCred, ":") {
			s.skipped = true
			return
		}

		creds := strings.Split(randomCred, ":")
		getUrl := creds[0] + ":" + creds[1] + "?domain=" + domain
		resp, err := session.Get(ctx, getUrl, "", map[string]string{
			"X-BLOBR-KEY": creds[2], "User-Agent": "subfinder",
		})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []string
		var response Response
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()
		if len(response.Subdomains) > 0 {
			subdomains = response.Subdomains
		}

		for _, subdomain := range subdomains {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}

	}()
	return results
}

func (s *Source) Name() string {
	return "redhuntlabs"
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
