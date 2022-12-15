// Package shodan logic
package shodan

import (
	"context"
	"fmt"
	"time"

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
	return &Shodan{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (s *Shodan) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			s.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.ApiKeys(), s.Name())
		if randomApiKey == "" {
			s.Skipped = true
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
			s.Errors++
			return
		}

		if response.Error != "" {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error),
			}
			s.Errors++
			return
		}

		for _, data := range response.Subdomains {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Subdomain, Value: fmt.Sprintf("%s.%s", data, domain),
			}
			s.Results++
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
