// Package windvane logic
package windvane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type response struct {
	Code int          `json:"code"`
	Msg  string       `json:"msg"`
	Data responseData `json:"data"`
}

type responseData struct {
	List         []domainEntry `json:"list"`
	PageResponse pageInfo      `json:"page_response"`
}

type domainEntry struct {
	Domain string `json:"domain"`
}

type pageInfo struct {
	Total     string `json:"total"`
	Count     string `json:"count"`
	TotalPage string `json:"total_page"`
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

		headers := map[string]string{"Content-Type": "application/json", "X-Api-Key": randomApiKey}

		page := 1
		count := 1000
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var resp *http.Response
			var err error

			requestBody, _ := json.Marshal(map[string]interface{}{"domain": domain, "page_request": map[string]int{"page": page, "count": count}})
			resp, err = session.Post(ctx, "https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService/ListSubDomain",
				"", headers, bytes.NewReader(requestBody))

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			defer session.DiscardHTTPResponse(resp)

			var windvaneResponse response
			err = json.NewDecoder(resp.Body).Decode(&windvaneResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			for _, record := range windvaneResponse.Data.List {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Domain}:
					s.results++
				}
			}

			pageInfo := windvaneResponse.Data.PageResponse
			var totalRecords, recordsPerPage int

			if totalRecords, err = strconv.Atoi(pageInfo.Total); err != nil {
				break
			}
			if recordsPerPage, err = strconv.Atoi(pageInfo.Count); err != nil {
				break
			}

			if (page-1)*recordsPerPage >= totalRecords {
				break
			}

			page++
		}

	}()

	return results
}

func (s *Source) Name() string {
	return "windvane"
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
