// Package redhuntlabs logic
package redhuntlabs

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type Response struct {
	Subdomains []string         `json:"subdomains"`
	Metadata   ResponseMetadata `json:"metadata"`
}

type ResponseMetadata struct {
	ResultCount int `json:"result_count"`
	PageSize    int `json:"page_size"`
	PageNumber  int `json:"page_number"`
}

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	pageSize := 1000
	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomCred := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomCred == "" || !strings.Contains(randomCred, ":") {
			s.skipped = true
			return
		}

		creds := strings.Split(randomCred, ":")
		baseUrl := creds[0] + ":" + creds[1]
		getUrl := baseUrl + "?domain=" + domain + "&page=1&page_size=" + strconv.Itoa(pageSize)
		resp, err := session.Get(ctx, getUrl, "", map[string]string{
			"X-BLOBR-KEY": creds[2], "User-Agent": "subfinder",
		})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: errors.New("if you get a 'limit has been reached' error, head over to https://devportal.redhuntlabs.com")}
			session.DiscardHTTPResponse(resp)
			return
		}
		var response Response
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()
		if response.Metadata.ResultCount > pageSize {
			totalPages := (response.Metadata.ResultCount + pageSize - 1) / pageSize
			for page := 1; page <= totalPages; page++ {
				getUrl = baseUrl + "?domain=" + domain + "&page=" + strconv.Itoa(page) + "&page_size=" + strconv.Itoa(pageSize)
				resp, err := session.Get(ctx, getUrl, "", map[string]string{
					"X-BLOBR-KEY": creds[2], "User-Agent": "subfinder",
				})
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: errors.New("if you get a 'limit has been reached' error, head over to https://devportal.redhuntlabs.com/ for upgrading your subscription")}
					session.DiscardHTTPResponse(resp)
					continue
				}

				var subdomains []string
				err = jsoniter.NewDecoder(resp.Body).Decode(&response)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					resp.Body.Close()
					continue
				}

				resp.Body.Close()
				if len(response.Subdomains) > 0 {
					subdomains = response.Subdomains
				}

				for _, subdomain := range subdomains {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				}
			}
		} else {
			if len(response.Subdomains) > 0 {
				for _, subdomain := range response.Subdomains {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				}
			}
		}

	}()
	return results
}

func (s *Source) Name() string {
	return "redhuntlabs"
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
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
