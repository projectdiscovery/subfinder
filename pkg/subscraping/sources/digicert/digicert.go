package digicert

import (
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/subfinder/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

type responseData struct {
	Data struct {
		CertificateDetail []struct {
			CommonName      string   `json:"string"`
			SubjectAltNames []string `json:"subjectAlternativeNames"`
		} `json:"certificateDetail"`
	} `json:"data"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		resp, err := session.Client.Get(fmt.Sprintf("https://ssltools.digicert.com/chainTester/webservice/ctsearch/search?keyword=%s", domain), "", nil)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		response := responseData{}
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		for _, cert := range response.Data.CertificateDetail {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: strings.TrimPrefix(strings.ToLower(cert.CommonName), "*.")}

			for _, subdomain := range cert.SubjectAltNames {
				subdomain := strings.TrimPrefix(strings.ToLower(subdomain), "*.")

				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		}

		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "digicert"
}
