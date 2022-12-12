// Package zoomeye logic
package zoomeye

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// zoomAuth holds the ZoomEye credentials
type zoomAuth struct {
	User string `json:"username"`
	Pass string `json:"password"`
}

type loginResp struct {
	JWT string `json:"access_token"`
}

// search results
type zoomeyeResults struct {
	Matches []struct {
		Site    string   `json:"site"`
		Domains []string `json:"domains"`
	} `json:"matches"`
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
	username string
	password string
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
		if randomApiKey.username == "" || randomApiKey.password == "" {
			s.skipped = true
			return
		}

		jwt, err := doLogin(ctx, session, randomApiKey)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		// check if jwt is null
		if jwt == "" {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error, Error: errors.New("could not log into zoomeye"),
			}
			s.errors++
			return
		}

		headers := map[string]string{
			"Authorization": fmt.Sprintf("JWT %s", jwt),
			"Accept":        "application/json",
			"Content-Type":  "application/json",
		}
		for currentPage := 0; currentPage <= 100; currentPage++ {
			api := fmt.Sprintf("https://api.zoomeye.org/web/search?query=hostname:%s&page=%d", domain, currentPage)
			resp, err := session.Get(ctx, api, "", headers)
			isForbidden := resp != nil && resp.StatusCode == http.StatusForbidden
			if err != nil {
				if !isForbidden && currentPage == 0 {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
				}
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			for _, r := range res.Matches {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: r.Site}
				s.results++
				for _, domain := range r.Domains {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: domain}
					s.results++
				}
			}
		}
	}()

	return results
}

// doLogin performs authentication on the ZoomEye API
func doLogin(ctx context.Context, session *subscraping.Session, randomApiKey apiKey) (string, error) {
	creds := &zoomAuth{
		User: randomApiKey.username,
		Pass: randomApiKey.password,
	}
	body, err := json.Marshal(&creds)
	if err != nil {
		return "", err
	}
	resp, err := session.SimplePost(ctx, "https://api.zoomeye.org/user/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		session.DiscardHTTPResponse(resp)
		return "", err
	}

	defer resp.Body.Close()

	var login loginResp
	err = json.NewDecoder(resp.Body).Decode(&login)
	if err != nil {
		return "", err
	}
	return login.JWT, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeye"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
