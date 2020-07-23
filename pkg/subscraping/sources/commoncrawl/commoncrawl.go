package commoncrawl

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

const indexURL = "https://index.commoncrawl.org/collinfo.json"

type indexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

// Source is the passive scraping agent
type Source struct{}

var years = [...]string{"2020", "2019", "2018", "2017"}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		resp, err := session.SimpleGet(ctx, indexURL)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			close(results)
			return
		}

		indexes := []indexResponse{}
		err = jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			close(results)
			return
		}
		resp.Body.Close()

		searchIndexes := make(map[string]string)
		for _, year := range years {
			for _, index := range indexes {
				if strings.Contains(index.ID, year) {
					if _, ok := searchIndexes[year]; !ok {
						searchIndexes[year] = index.APIURL
						break
					}
				}
			}
		}

		for _, apiURL := range searchIndexes {
			further := s.getSubdomains(ctx, apiURL, domain, session, results)
			if !further {
				break
			}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "commoncrawl"
}

func (s *Source) getSubdomains(ctx context.Context, searchURL, domain string, session *subscraping.Session, results chan subscraping.Result) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			resp, err := session.SimpleGet(ctx, fmt.Sprintf("%s?url=*.%s&output=json", searchURL, domain))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return false
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return false
			}
			resp.Body.Close()

			src, _ := url.QueryUnescape(string(body))

			for _, subdomain := range session.Extractor.FindAllString(src, -1) {
				subdomain = strings.TrimPrefix(subdomain, "25")

				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
			return true
		}
	}
}
