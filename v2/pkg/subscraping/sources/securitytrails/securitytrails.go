// Package securitytrails logic
package securitytrails

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// SecurityTrails is the KeyApiSource that handles access to the SecurityTrails data source.
type SecurityTrails struct {
	*subscraping.KeyApiSource
}

func NewSecurityTrails() *SecurityTrails {
	return &SecurityTrails{KeyApiSource: &subscraping.KeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (s *SecurityTrails) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(s.ApiKeys(), s.Name())
		if randomApiKey == "" {
			return
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain), "", map[string]string{"APIKEY": randomApiKey})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var securityTrailsResponse response
		err = jsoniter.NewDecoder(resp.Body).Decode(&securityTrailsResponse)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range securityTrailsResponse.Subdomains {
			if strings.HasSuffix(subdomain, ".") {
				subdomain += domain
			} else {
				subdomain = subdomain + "." + domain
			}

			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *SecurityTrails) Name() string {
	return "securitytrails"
}

func (s *SecurityTrails) IsDefault() bool {
	return true
}

func (s *SecurityTrails) HasRecursiveSupport() bool {
	return true
}

func (s *SecurityTrails) SourceType() string {
	return subscraping.TYPE_API
}
