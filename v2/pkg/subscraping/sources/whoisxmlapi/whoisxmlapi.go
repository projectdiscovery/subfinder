// Package whoisxmlapi logic
package whoisxmlapi

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Search string `json:"search"`
	Result Result `json:"result"`
}

type Result struct {
	Count   int      `json:"count"`
	Records []Record `json:"records"`
}

type Record struct {
	Domain    string `json:"domain"`
	FirstSeen int    `json:"firstSeen"`
	LastSeen  int    `json:"lastSeen"`
}

// Source is the passive scraping agent
type Source struct{}

var apiKeys []string

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(apiKeys)
		if randomApiKey == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://subdomains.whoisxmlapi.com/api/v1?apiKey=%s&domainName=%s", randomApiKey, domain))
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

		for _, record := range data.Result.Records {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Domain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "whoisxmlapi"
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
	apiKeys = keys
}
