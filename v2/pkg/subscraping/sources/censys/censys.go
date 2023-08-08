// Package censys logic
package censys

import (
	"context"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	maxCensysPages = 10
	maxPerPage     = 100
)

type response struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Result result `json:"result"`
}

type result struct {
	Query      string  `json:"query"`
	Total      float64 `json:"total"`
	DurationMS int     `json:"duration_ms"`
	Hits       []hit   `json:"hits"`
	Links      links   `json:"links"`
}

type hit struct {
	Parsed            parsed   `json:"parsed"`
	Names             []string `json:"names"`
	FingerprintSha256 string   `json:"fingerprint_sha256"`
}

type parsed struct {
	ValidityPeriod validityPeriod `json:"validity_period"`
	SubjectDN      string         `json:"subject_dn"`
	IssuerDN       string         `json:"issuer_dn"`
}

type validityPeriod struct {
	NotAfter  string `json:"not_after"`
	NotBefore string `json:"not_before"`
}

type links struct {
	Next string `json:"next"`
	Prev string `json:"prev"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type apiKey struct {
	token  string
	secret string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.token == "" || randomApiKey.secret == "" {
			s.skipped = true
			return
		}

		certSearchEndpoint := "https://search.censys.io/api/v2/certificates/search"
		cursor := ""
		currentPage := 1
		for {
			certSearchEndpointUrl, err := urlutil.Parse(certSearchEndpoint)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			certSearchEndpointUrl.Params.Add("q", domain)
			certSearchEndpointUrl.Params.Add("per_page", strconv.Itoa(maxPerPage))
			if cursor != "" {
				certSearchEndpointUrl.Params.Add("cursor", cursor)
			}

			resp, err := session.HTTPRequest(
				ctx,
				"GET",
				certSearchEndpointUrl.String(),
				"",
				nil,
				nil,
				subscraping.BasicAuth{Username: randomApiKey.token, Password: randomApiKey.secret},
			)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var censysResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, hit := range censysResponse.Result.Hits {
				for _, name := range hit.Names {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: name}
					s.results++
				}
			}

			// Exit the censys enumeration if last page is reached
			cursor = censysResponse.Result.Links.Next
			if cursor == "" || currentPage >= maxCensysPages {
				break
			}
			currentPage++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "censys"
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
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
