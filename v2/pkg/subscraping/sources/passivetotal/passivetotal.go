// Package passivetotal logic
package passivetotal

import (
	"bytes"
	"context"
	"regexp"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

var passiveTotalFilterRegex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}\\032`)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
}

type apiKey struct {
	username string
	password string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	startTime := time.Now()

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.username == "" || randomApiKey.password == "" {
			return
		}

		// Create JSON Get body
		var request = []byte(`{"query":"` + domain + `"}`)

		resp, err := session.HTTPRequest(
			ctx,
			"GET",
			"https://api.passivetotal.org/v2/enrichment/subdomains",
			"",
			map[string]string{"Content-Type": "application/json"},
			bytes.NewBuffer(request),
			subscraping.BasicAuth{Username: randomApiKey.username, Password: randomApiKey.password},
		)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		for _, subdomain := range data.Subdomains {
			// skip entries like xxx.xxx.xxx.xxx\032domain.tld
			if passiveTotalFilterRegex.MatchString(subdomain) {
				continue
			}
			finalSubdomain := subdomain + "." + domain
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: finalSubdomain}
		}
		s.timeTaken = time.Since(startTime)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "passivetotal"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) TimeTaken() time.Duration {
	return s.timeTaken
}
