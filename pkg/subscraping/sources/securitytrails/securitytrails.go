// Package securitytrails logic
package securitytrails

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
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
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			stats.Skipped = true
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
				stats.Requests++
				resp, err = session.Post(ctx, "https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true", "",
					headers, bytes.NewReader(requestBody))
			} else {
				stats.Requests++
				resp, err = session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/scroll/%s", scrollId), "", headers)
			}

			if err != nil && ptr.Safe(resp).StatusCode == 403 {
				stats.Requests++
				resp, err = session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain), "", headers)
			}

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var securityTrailsResponse response
			err = jsoniter.NewDecoder(resp.Body).Decode(&securityTrailsResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				stats.Errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			for _, record := range securityTrailsResponse.Records {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Hostname}:
					stats.Results++
				}
				if maxResults > 0 && stats.Results >= maxResults {
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
				stats.Results++
				if maxResults > 0 && stats.Results >= maxResults {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
