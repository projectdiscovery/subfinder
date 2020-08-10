package shodan

import (
	"context"
	"strconv"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type shodanResult struct {
	Matches []shodanObject `json:"matches"`
	Result  int            `json:"result"`
	Error   string         `json:"error"`
}

type shodanObject struct {
	Hostnames []string `json:"hostnames"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		if session.Keys.Shodan == "" {
			return
		}

		for currentPage := 0; currentPage <= 10; currentPage++ {
			resp, err := session.SimpleGet(ctx, "https://api.shodan.io/shodan/host/search?query=hostname:"+domain+"&page="+strconv.Itoa(currentPage)+"&key="+session.Keys.Shodan)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return
			}

			var response shodanResult
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if response.Error != "" || len(response.Matches) == 0 {
				return
			}

			for _, block := range response.Matches {
				for _, hostname := range block.Hostnames {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: hostname}
				}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
}
