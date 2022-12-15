// Package certspotter logic
package certspotter

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type certspotterObject struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

// CertSpotter is the KeyApiSource that handles access to the CertSpotter data source.
type CertSpotter struct {
	*subscraping.KeyApiSource
}

func NewCertSpotter() *CertSpotter {
	return &CertSpotter{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (c *CertSpotter) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			c.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(c.ApiKeys(), c.Name())
		if randomApiKey == "" {
			c.Skipped = true
			return
		}

		headers := map[string]string{"Authorization": "Bearer " + randomApiKey}
		cookies := ""

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain), cookies, headers)
		if err != nil {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			c.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response []certspotterObject
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			c.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		for _, cert := range response {
			for _, subdomain := range cert.DNSNames {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: subdomain}
				c.Results++
			}
		}

		// if the number of responses is zero, close the channel and return.
		if len(response) == 0 {
			return
		}

		id := response[len(response)-1].ID
		for {
			reqURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&after=%s", domain, id)

			resp, err := session.Get(ctx, reqURL, cookies, headers)
			if err != nil {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
				c.Errors++
				return
			}

			var response []certspotterObject
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
				c.Errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if len(response) == 0 {
				break
			}

			for _, cert := range response {
				for _, subdomain := range cert.DNSNames {
					results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: subdomain}
					c.Results++
				}
			}

			id = response[len(response)-1].ID
		}
	}()

	return results
}

// Name returns the name of the source
func (c *CertSpotter) Name() string {
	return "certspotter"
}

func (c *CertSpotter) IsDefault() bool {
	return true
}

func (c *CertSpotter) HasRecursiveSupport() bool {
	return true
}

func (c *CertSpotter) SourceType() string {
	return subscraping.TYPE_CERT
}
