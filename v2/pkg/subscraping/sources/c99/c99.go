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

		if session.Keys.C99 == "" {
			return
		}

		searchURL := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json", session.Keys.C99, domain)
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
