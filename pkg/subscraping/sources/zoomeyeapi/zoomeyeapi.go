package zoomeyeapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// search results
type zoomeyeResults struct {
	Code  int `json:"code"`
	Total int `json:"total"`
	Data  []struct {
		Domain string `json:"domain"`
	} `json:"data"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken atomic.Int64 // nanoseconds; cast to time.Duration on read
	errors    atomic.Int32
	results   atomic.Int32
	requests  atomic.Int32
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors.Store(0)
	s.results.Store(0)
	s.requests.Store(0)

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken.Store(int64(time.Since(startTime)))
			close(results)
		}(time.Now())

		reportError := func(err error) {
			s.errors.Add(1)
			select {
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
			case <-ctx.Done():
			}
		}

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		randomApiInfo := strings.Split(randomApiKey, ":")
		if len(randomApiInfo) != 2 {
			s.skipped = true
			return
		}
		host := randomApiInfo[0]
		apiKey := randomApiInfo[1]

		headers := map[string]string{
			"API-KEY":      apiKey,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}
		const pageSize = 1000
		// Search web assets explicitly; the v2 API defaults to IPv4 assets.
		query := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "domain=%q", domain))
		api := fmt.Sprintf("https://api.%s/v2/search", host)
		for currentPage := 1; ; currentPage++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			body, err := json.Marshal(struct {
				Query    string `json:"qbase64"`
				Page     int    `json:"page"`
				PageSize int    `json:"pagesize"`
				Fields   string `json:"fields"`
				SubType  string `json:"sub_type"`
			}{
				Query: query, Page: currentPage, PageSize: pageSize,
				Fields: "domain", SubType: "web",
			})
			if err != nil {
				reportError(fmt.Errorf("encode ZoomEye search request: %w", err))
				return
			}
			s.requests.Add(1)
			resp, err := session.Post(ctx, api, "", headers, bytes.NewReader(body))
			if err != nil {
				if resp != nil {
					_ = resp.Body.Close()
				}
				reportError(err)
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)
			_ = resp.Body.Close()

			if err != nil {
				reportError(fmt.Errorf("decode ZoomEye search response: %w", err))
				return
			}
			if res.Code != 60000 {
				reportError(fmt.Errorf("ZoomEye search failed with code %d", res.Code))
				return
			}
			for _, r := range res.Data {
				if r.Domain == "" {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: r.Domain}:
					s.results.Add(1)
				}
			}
			if len(res.Data) == 0 || currentPage >= (res.Total-1)/pageSize+1 {
				return
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeyeapi"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Skipped:   s.skipped,
		Requests:  int(s.requests.Load()),
	}
}
