// Package redhuntlabs logic
package redhuntlabs

import (
	"context"
	"fmt"
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

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" || !strings.Contains(randomApiKey, ":") {
			s.skipped = true
			return
		}

		randomApiInfo := strings.Split(randomApiKey, ":")
		if len(randomApiInfo) != 3 {
			s.skipped = true
			return
		}
		baseUrl := randomApiInfo[0] + ":" + randomApiInfo[1]
		requestHeaders := map[string]string{"X-BLOBR-KEY": randomApiInfo[2], "User-Agent": "subfinder"}
		getUrl := fmt.Sprintf("%s?domain=%s&page=1&page_size=%d", baseUrl, domain, pageSize)
		resp, err := session.Get(ctx, getUrl, "", requestHeaders)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("encountered error: %v; note: if you get a 'limit has been reached' error, head over to https://devportal.redhuntlabs.com", err)}
			session.DiscardHTTPResponse(resp)
			s.errors++
			return
		}
		var response Response
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			s.errors++
			return
		}

		session.DiscardHTTPResponse(resp)
		if response.Metadata.ResultCount > pageSize {
			totalPages := (response.Metadata.ResultCount + pageSize - 1) / pageSize
			for page := 1; page <= totalPages; page++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				getUrl = fmt.Sprintf("%s?domain=%s&page=%d&page_size=%d", baseUrl, domain, page, pageSize)
				resp, err := session.Get(ctx, getUrl, "", requestHeaders)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("encountered error: %v; note: if you get a 'limit has been reached' error, head over to https://devportal.redhuntlabs.com", err)}
					session.DiscardHTTPResponse(resp)
					s.errors++
					return
				}

				err = jsoniter.NewDecoder(resp.Body).Decode(&response)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					session.DiscardHTTPResponse(resp)
					s.errors++
					continue
				}

				session.DiscardHTTPResponse(resp)

				for _, subdomain := range response.Subdomains {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
						s.results++
					}
				}
			}
		} else {
			for _, subdomain := range response.Subdomains {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results++
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
