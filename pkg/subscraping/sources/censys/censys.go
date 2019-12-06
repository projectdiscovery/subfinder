package censys

import (
	"bytes"
	"context"
	"net/http"
	"strconv"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
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
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.CensysToken == "" || session.Keys.CensysSecret == "" {
			close(results)
			return
		}
		var response response

		currentPage := 1
		for {
			var request = []byte(`{"query":"` + domain + `", "page":` + strconv.Itoa(currentPage) + `, "fields":["parsed.names","parsed.extensions.subject_alt_name.dns_names"], "flatten":true}`)

			req, err := http.NewRequest("POST", "https://www.censys.io/api/v1/search/certificates", bytes.NewReader(request))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}
			req.SetBasicAuth(session.Keys.CensysToken, session.Keys.CensysSecret)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")

			resp, err := session.Client.Do(req)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}

			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(results)
				return
			}
			resp.Body.Close()

			// Exit the censys enumeration if max pages is reached
			if currentPage >= response.Metadata.Pages || currentPage >= maxCensysPages {
				break
			}

			for _, res := range response.Results {
				for _, part := range res.Data {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: part}
				}
				for _, part := range res.Data1 {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: part}
				}
			}

			currentPage++
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "censys"
}
