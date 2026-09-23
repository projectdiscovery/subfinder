// Package fofa logic
package fofa

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type fofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken atomic.Int64 // nanoseconds; cast to time.Duration on read
	errors    atomic.Int32
	results   atomic.Int32
	requests  atomic.Int32
	skipped   bool
}

type apiKey struct {
	username string
	secret   string
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

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.username == "" || randomApiKey.secret == "" {
			s.skipped = true
			return
		}

		// fofa api doc https://fofa.info/static_pages/api_help
		qbase64 := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "domain=\"%s\"", domain))
		s.requests.Add(1)
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://fofa.info/api/v1/search/all?full=true&fields=host&page=1&size=10000&email=%s&key=%s&qbase64=%s", randomApiKey.username, randomApiKey.secret, qbase64))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}

		var response fofaResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors.Add(1)
			session.DiscardHTTPResponse(resp)
			return
		}
		session.DiscardHTTPResponse(resp)

		if response.Error {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.ErrMsg),
			}
			s.errors.Add(1)
			return
		}

		if response.Size > 0 {
			for _, subdomain := range response.Results {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if strings.HasPrefix(strings.ToLower(subdomain), "http://") || strings.HasPrefix(strings.ToLower(subdomain), "https://") {
					subdomain = subdomain[strings.Index(subdomain, "//")+2:]
				}
				re := regexp.MustCompile(`:\d+$`)
				if re.MatchString(subdomain) {
					subdomain = re.ReplaceAllString(subdomain, "")
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				s.results.Add(1)
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "fofa"
}

func (s *Source) IsDefault() bool {
	return true
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
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    int(s.errors.Load()),
		Results:   int(s.results.Load()),
		Requests:  int(s.requests.Load()),
		TimeTaken: time.Duration(s.timeTaken.Load()),
		Skipped:   s.skipped,
	}
}
