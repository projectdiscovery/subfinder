// Package securitytrails logic
package securitytrails

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/utils/ptr"
)

type response struct {
	Meta struct {
		ScrollID string `json:"scroll_id"`
	} `json:"meta"`
	Records []struct {
		Hostname string `json:"hostname"`
	} `json:"records"`
	Subdomains []string `json:"subdomains"`
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

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		// Honor an optional per-source result limit (0 = no limit) so a single
		// domain can't drain an API quota by paginating to the end.
		maxResults := session.MaxResults

		var scrollId string
		headers := map[string]string{"Content-Type": "application/json", "APIKEY": randomApiKey}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var resp *http.Response
			var err error

			if scrollId == "" {
				var requestBody = fmt.Appendf(nil, `{"query":"apex_domain='%s'"}`, domain)
				s.requests.Add(1)
				resp, err = session.Post(ctx, "https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true", "",
					headers, bytes.NewReader(requestBody))
			} else {
				s.requests.Add(1)
				resp, err = session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/scroll/%s", scrollId), "", headers)
			}

			if err != nil && ptr.Safe(resp).StatusCode == 403 {
				s.requests.Add(1)
				resp, err = session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain), "", headers)
			}

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return
			}

			var securityTrailsResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&securityTrailsResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors.Add(1)
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			for _, record := range securityTrailsResponse.Records {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Hostname}:
					s.results.Add(1)
				}
				if maxResults > 0 && s.results >= maxResults {
					return
				}
			}

			for _, subdomain := range securityTrailsResponse.Subdomains {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if strings.HasSuffix(subdomain, ".") {
					subdomain += domain
				} else {
					subdomain = subdomain + "." + domain
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				s.results.Add(1)
				if maxResults > 0 && s.results >= maxResults {
					return
				}
			}

			scrollId = securityTrailsResponse.Meta.ScrollID

			if scrollId == "" {
				break
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "securitytrails"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
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
