// Package shodan logic
package shodan

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type dnsdbLookupResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Result     int      `json:"result"`
	Error      string   `json:"error"`
}

// Shodan is the KeyApiSource that handles access to the Shodan data source.
type Shodan struct {
	*subscraping.KeyApiSource
}

func NewShodan() *Shodan {
	return &Shodan{KeyApiSource: &subscraping.KeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (s *Shodan) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(s.ApiKeys(), s.Name())
		if randomApiKey == "" {
			return
		}

		searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, randomApiKey)
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
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", data, domain)}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Shodan) Name() string {
	return "shodan"
}

func (s *Shodan) IsDefault() bool {
	return true
}

func (s *Shodan) SourceType() string {
	return subscraping.TYPE_API
}
