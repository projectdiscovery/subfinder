package shodan

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/subfinder/subfinder/pkg/subscraping"
)

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
		if session.Keys.Censys == "" {
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
				close(results)
				return
			}
			resp.Body.Close()

			fmt.Printf("%v\n")
			if response.Error != "" {
				close(results)
				return
			}

			for _, block := range response.Matches {
				for _, hostname := range block.Hostnames {

					if strings.Contains(hostname, "*.") {
						hostname = strings.Split(hostname, "*.")[1]
					}

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
