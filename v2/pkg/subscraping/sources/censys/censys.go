// Package censys logic
package censys

import (
	"bytes"
	"context"
	"strconv"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const maxCensysPages = 10

type resultsq struct {
	Data  []string `json:"parsed.extensions.subject_alt_name.dns_names"`
	Data1 []string `json:"parsed.names"`
}

type response struct {
	Results  []resultsq `json:"results"`
	Metadata struct {
		Pages int `json:"pages"`
	} `json:"metadata"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys []apiKey
}

type apiKey struct {
	token  string
	secret string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.token == "" || randomApiKey.secret == "" {
			return
		}

		currentPage := 1
		for {
			var request = []byte(`{"query":"` + domain + `", "page":` + strconv.Itoa(currentPage) + `, "fields":["parsed.names","parsed.extensions.subject_alt_name.dns_names"], "flatten":true}`)

			resp, err := session.HTTPRequest(
				ctx,
				"POST",
				"https://search.censys.io/api/v1/search/certificates",
				"",
				map[string]string{"Content-Type": "application/json", "Accept": "application/json"},
				bytes.NewReader(request),
				subscraping.BasicAuth{Username: randomApiKey.token, Password: randomApiKey.secret},
			)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}

			var censysResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, res := range censysResponse.Results {
				for _, part := range res.Data {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: part}
				}
				for _, part := range res.Data1 {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: part}
				}
			}

			// Exit the censys enumeration if max pages is reached
			if currentPage >= censysResponse.Metadata.Pages || currentPage >= maxCensysPages {
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
