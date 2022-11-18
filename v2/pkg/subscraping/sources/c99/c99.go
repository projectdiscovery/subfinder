// Package c99 logic
package c99

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// C99 is the KeyApiSource that handles access to the C99 data source.
type C99 struct {
	*subscraping.KeyApiSource
}

type dnsdbLookupResponse struct {
	Success    bool `json:"success"`
	Subdomains []struct {
		Subdomain  string `json:"subdomain"`
		IP         string `json:"ip"`
		Cloudflare bool   `json:"cloudflare"`
	} `json:"subdomains"`
	Error string `json:"error"`
}

func NewC99() *C99 {
	return &C99{KeyApiSource: &subscraping.KeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (c *C99) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(c.ApiKeys(), c.Name())
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
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			return
		}

		if response.Error != "" {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error)}
			return
		}

		for _, data := range response.Subdomains {
			if !strings.HasPrefix(data.Subdomain, ".") {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: data.Subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (c *C99) Name() string {
	return "c99"
}

func (c *C99) IsDefault() bool {
	return true
}

func (c *C99) SourceType() string {
	return subscraping.TYPE_API
}
