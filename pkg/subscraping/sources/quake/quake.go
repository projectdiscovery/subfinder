// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		}
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
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
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		// quake api doc https://quake.360.cn/quake/#/help
		var pageSize = 500
		var start = 0
		var totalResults = -1

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var requestBody = fmt.Appendf(nil, `{"query":"domain: %s", "include":["service.http.host"], "latest": true, "size":%d, "start":%d}`, domain, pageSize, start)
			resp, err := session.Post(ctx, "https://quake.360.net/api/v3/search/quake_service", "", map[string]string{
				"Content-Type": "application/json", "X-QuakeToken": randomApiKey,
			}, bytes.NewReader(requestBody))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var response quakeResults
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}
			session.DiscardHTTPResponse(resp)

			if response.Code != 0 {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
				}
				s.errors++
				return
			}

			if totalResults == -1 {
				totalResults = response.Meta.Pagination.Total
			}

			for _, quakeDomain := range response.Data {
				select {
				case <-ctx.Done():
					return
				default:
				}
				subdomain := quakeDomain.Service.HTTP.Host
				if strings.ContainsAny(subdomain, "暂无权限") {
					continue
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				s.results++
			}

			if len(response.Data) == 0 || start+pageSize >= totalResults {
				break
			}

			start += pageSize
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "quake"
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
