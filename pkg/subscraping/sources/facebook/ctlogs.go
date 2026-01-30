package facebook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/utils/generic"
	urlutil "github.com/projectdiscovery/utils/url"
)

// source: https://developers.facebook.com/tools/ct
// api-docs: https://developers.facebook.com/docs/certificate-transparency-api
// ratelimit: ~20,000 req/hour per appID https://developers.facebook.com/docs/graph-api/overview/rate-limiting/

var (
	domainsPerPage = "1000"
	authUrl        = "https://graph.facebook.com/oauth/access_token?client_id=%s&client_secret=%s&grant_type=client_credentials"
	domainsUrl     = "https://graph.facebook.com/certificates?fields=domains&access_token=%s&query=%s&limit=" + domainsPerPage
)

type apiKey struct {
	AppID       string
	Secret      string
	AccessToken string // obtained by calling
	// https://graph.facebook.com/oauth/access_token?client_id=APP_ID&client_secret=APP_SECRET&grant_type=client_credentials
	Error error // error while fetching access token
}

// FetchAccessToken fetches the access token for the api key
// using app id and secret
func (k *apiKey) FetchAccessToken() {
	if generic.EqualsAny("", k.AppID, k.Secret) {
		k.Error = fmt.Errorf("invalid app id or secret")
		return
	}
	resp, err := retryablehttp.Get(fmt.Sprintf(authUrl, k.AppID, k.Secret))
	if err != nil {
		k.Error = err
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			gologger.Error().Msgf("error closing response body: %s", err)
		}
	}()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		k.Error = err
		return
	}
	auth := &authResponse{}
	if err := json.Unmarshal(bin, auth); err != nil {
		k.Error = err
		return
	}
	if auth.AccessToken == "" {
		k.Error = fmt.Errorf("invalid response from facebook got %v", string(bin))
		return
	}
	k.AccessToken = auth.AccessToken
}

// IsValid returns true if the api key is valid
func (k *apiKey) IsValid() bool {
	return k.AccessToken != ""
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

	if len(s.apiKeys) == 0 {
		s.skipped = true
		close(results)
		return results
	}

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		key := subscraping.PickRandom(s.apiKeys, s.Name())
		domainsURL := fmt.Sprintf(domainsUrl, key.AccessToken, domain)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			s.requests++
			resp, err := session.Get(ctx, domainsURL, "", nil)
			if err != nil {
				s.errors++
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return
			}
			bin, err := io.ReadAll(resp.Body)
			if err != nil {
				s.errors++
				gologger.Verbose().Msgf("failed to read response body: %s\n", err)
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				return
			}
			session.DiscardHTTPResponse(resp)
			response := &response{}
			if err := json.Unmarshal(bin, response); err != nil {
				s.errors++
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("failed to unmarshal response: %s: %w", string(bin), err)}
				return
			}
			for _, v := range response.Data {
				for _, domain := range v.Domains {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: domain}:
						s.results++
					}
				}
			}
			if response.Paging.Next == "" {
				break
			}
			domainsURL = updateParamInURL(response.Paging.Next, "limit", domainsPerPage)
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "facebook"
}

// IsDefault returns true if the source should be queried by default
func (s *Source) IsDefault() bool {
	return true
}

// accepts subdomains (e.g. subdomain.domain.tld)
// but also returns all SANs for a certificate which may not match the domain
func (s *Source) HasRecursiveSupport() bool {
	return true
}

// KeyRequirement returns the API key requirement level for this source
func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

// NeedsKey returns true if the source requires an API key
func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

// AddApiKeys adds api keys to the source
func (s *Source) AddApiKeys(keys []string) {
	allapikeys := subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		apiKey := apiKey{AppID: k, Secret: v}
		apiKey.FetchAccessToken()
		if apiKey.Error != nil {
			gologger.Warning().Msgf("Could not fetch access token for %s: %s\n", k, apiKey.Error)
		}
		return apiKey
	})
	// filter out invalid keys
	for _, key := range allapikeys {
		if key.IsValid() {
			s.apiKeys = append(s.apiKeys, key)
		}
	}
}

// Statistics returns the statistics for the source
func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}

func updateParamInURL(url, param, value string) string {
	urlx, err := urlutil.Parse(url)
	if err != nil {
		return url
	}
	urlx.Params.Set(param, value)
	return urlx.String()
}
