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
		if session.Keys.Shodan == "" {
			close(results)
			return
		}

		for currentPage := 0; currentPage <= 10; currentPage++ {
			resp, err := session.NormalGet("https://api.shodan.io/shodan/host/search?query=hostname:" + domain + "&page=" + strconv.Itoa(currentPage) + "&key=" + session.Keys.Shodan)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}

			var response shodanResult
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(results)
				return
			}
			resp.Body.Close()

			if response.Error != "" || len(response.Matches) == 0 {
				close(results)
				return
			}

			for _, block := range response.Matches {
				for _, hostname := range block.Hostnames {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: hostname}
				}
			}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
}
