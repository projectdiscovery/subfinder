// Package censys logic
package censys

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	maxCensysPages = 10
	maxPerPage     = 100
	searchAPIUrl   = "https://api.platform.censys.io/v3/global/search/query"
	authorization  = "Authorization"
	bearerTokenFmt = "Bearer %s"
	acceptHeader   = "application/vnd.censys.api.v3.search.v1+json"
	orgHeader      = "X-Organization-ID"
)

type searchRequest struct {
	Query     string   `json:"query"`
	PageSize  int      `json:"page_size,omitempty"`
	PageToken string   `json:"page_token,omitempty"`
	Fields    []string `json:"fields,omitempty"`
}

type searchResponse struct {
	Result *searchResult `json:"result"`
}

type searchResult struct {
	Hits          []searchHit `json:"hits"`
	NextPageToken string      `json:"next_page_token"`
}

type searchHit struct {
	Certificate *certificateAsset `json:"certificate_v1"`
	Host        *hostAsset        `json:"host_v1"`
	WebProperty *webPropertyAsset `json:"webproperty_v1"`
}

type certificateAsset struct {
	Resource *certificateResource `json:"resource"`
}

type certificateResource struct {
	Names []string `json:"names"`
}

type hostAsset struct {
	Resource *hostResource `json:"resource"`
}

type hostResource struct {
	DNS *hostDNS `json:"dns"`
}

type hostDNS struct {
	Names []string `json:"names"`
}

type webPropertyAsset struct {
	Resource *webPropertyResource `json:"resource"`
}

type webPropertyResource struct {
	Hostname string `json:"hostname"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type apiKey struct {
	token string
	orgID string
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
		if randomApiKey.token == "" {
			s.skipped = true
			return
		}

		domainLower := strings.ToLower(domain)
		seen := make(map[string]struct{})
		cursor := ""
		currentPage := 1
		for {
			reqBody := searchRequest{
				Query:    domain,
				PageSize: maxPerPage,
			}
			if cursor != "" {
				reqBody.PageToken = cursor
			}

			payload, err := jsoniter.Marshal(reqBody)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				return
			}

			headers := map[string]string{
				"Content-Type": "application/json",
				"Accept":       acceptHeader,
				authorization:  fmt.Sprintf(bearerTokenFmt, randomApiKey.token),
			}
			if randomApiKey.orgID != "" {
				headers[orgHeader] = randomApiKey.orgID
			}

			resp, err := session.HTTPRequest(
				ctx,
				http.MethodPost,
				searchAPIUrl,
				"",
				headers,
				bytes.NewReader(payload),
				subscraping.BasicAuth{},
			)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var censysResponse searchResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&censysResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			if censysResponse.Result == nil || len(censysResponse.Result.Hits) == 0 {
				break
			}

			for _, hit := range censysResponse.Result.Hits {
				s.emitFromHit(hit, domainLower, seen, results)
			}

			cursor = censysResponse.Result.NextPageToken
			if cursor == "" || currentPage >= maxCensysPages {
				break
			}
			currentPage++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "censys"
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
	s.apiKeys = nil
	for _, key := range keys {
		raw := strings.TrimSpace(key)
		if raw == "" {
			continue
		}

		token := raw
		orgID := ""
		if strings.Contains(raw, ":") {
			parts := strings.SplitN(raw, ":", 2)
			token = strings.TrimSpace(parts[0])
			orgID = strings.TrimSpace(parts[1])
		}

		if token == "" {
			gologger.Warning().Msg("censys source encountered an entry without a PAT token; skipping")
			continue
		}

		s.apiKeys = append(s.apiKeys, apiKey{token: token, orgID: orgID})
	}
}

func (s *Source) emitFromHit(hit searchHit, domainLower string, seen map[string]struct{}, results chan subscraping.Result) {
	if hit.Certificate != nil && hit.Certificate.Resource != nil {
		for _, name := range hit.Certificate.Resource.Names {
			s.emitIfValid(name, domainLower, seen, results)
		}
	}

	if hit.Host != nil && hit.Host.Resource != nil && hit.Host.Resource.DNS != nil {
		for _, name := range hit.Host.Resource.DNS.Names {
			s.emitIfValid(name, domainLower, seen, results)
		}
	}

	if hit.WebProperty != nil && hit.WebProperty.Resource != nil {
		s.emitIfValid(hit.WebProperty.Resource.Hostname, domainLower, seen, results)
	}
}

func (s *Source) emitIfValid(candidate, domainLower string, seen map[string]struct{}, results chan subscraping.Result) {
	name, ok := sanitizeCandidate(candidate, domainLower)
	if !ok {
		return
	}
	if _, alreadySeen := seen[name]; alreadySeen {
		return
	}
	seen[name] = struct{}{}
	results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: name}
	s.results++
}

func sanitizeCandidate(value, domainLower string) (string, bool) {
	name := strings.TrimSpace(strings.TrimSuffix(value, "."))
	if name == "" {
		return "", false
	}
	name = strings.TrimPrefix(name, "*.")
	nameLower := strings.ToLower(name)
	if nameLower == domainLower || strings.HasSuffix(nameLower, "."+domainLower) {
		return nameLower, true
	}
	return "", false
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
