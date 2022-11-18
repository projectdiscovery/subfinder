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

// Censys is the CredsApiSource that handles access to the Censys data source.
type Censys struct {
	*subscraping.MultiPartKeyApiSource
}

func NewCensys() *Censys {
	return &Censys{MultiPartKeyApiSource: &subscraping.MultiPartKeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (c *Censys) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(c.ApiKeys(), c.Name())
		if randomApiKey.Username == "" || randomApiKey.Password == "" {
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
				subscraping.BasicAuth{Username: randomApiKey.Username, Password: randomApiKey.Password},
			)

			if err != nil {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}

			var censysResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
			if err != nil {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}

			resp.Body.Close()

			for _, res := range censysResponse.Results {
				for _, part := range res.Data {
					results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: part}
				}
				for _, part := range res.Data1 {
					results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: part}
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
func (c *Censys) Name() string {
	return "censys"
}

func (c *Censys) IsDefault() bool {
	return true
}

func (c *Censys) SourceType() string {
	return subscraping.TYPE_CERT
}
