// Package c99 logic
package c99

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

var apiKeys []string

type dnsdbLookupResponse struct {
	Success    bool `json:"success"`
	Subdomains []struct {
		Subdomain  string `json:"subdomain"`
		IP         string `json:"ip"`
		Cloudflare bool   `json:"cloudflare"`
	} `json:"subdomains"`
	Error string `json:"error"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		searchURL := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json", randomApiKey, domain)
		resp, err := session.SimpleGet(ctx, searchURL)
		if err != nil {
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		var response dnsdbLookupResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}

		if response.Error != "" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error)}
			return
		}

		for _, data := range response.Subdomains {
			if !strings.HasPrefix(data.Subdomain, ".") {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: data.Subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "c99"
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
