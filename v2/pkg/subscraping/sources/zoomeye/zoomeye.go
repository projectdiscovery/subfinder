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

// ZoomEye is the CredsKeyApiSource that handles access to the ZoomEye data source.
type ZoomEye struct {
	*subscraping.MultiPartKeyApiSource
}

func NewZoomEye() *ZoomEye {
	return &ZoomEye{
		MultiPartKeyApiSource: &subscraping.MultiPartKeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

// Run function returns all subdomains found with the service
func (z *ZoomEye) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			z.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(z.ApiKeys(), z.Name())
		if randomApiKey.Username == "" || randomApiKey.Password == "" {
			z.Skipped = true
			return
		}

		jwt, err := doLogin(ctx, session, randomApiKey)
		if err != nil {
			results <- subscraping.Result{Source: z.Name(), Type: subscraping.Error, Error: err}
			z.Errors++
			return
		}
		// check if jwt is null
		if jwt == "" {
			results <- subscraping.Result{
				Source: z.Name(), Type: subscraping.Error, Error: errors.New("could not log into zoomeye"),
			}
			z.Errors++
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
					results <- subscraping.Result{Source: z.Name(), Type: subscraping.Error, Error: err}
					z.Errors++
					session.DiscardHTTPResponse(resp)
				}
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)
			if err != nil {
				results <- subscraping.Result{Source: z.Name(), Type: subscraping.Error, Error: err}
				z.Errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			for _, r := range res.Matches {
				results <- subscraping.Result{Source: z.Name(), Type: subscraping.Subdomain, Value: r.Site}
				z.Results++
				for _, domain := range r.Domains {
					results <- subscraping.Result{Source: z.Name(), Type: subscraping.Subdomain, Value: domain}
					z.Results++
				}
			}
		}
	}()

	return results
}

// doLogin performs authentication on the ZoomEye API
func doLogin(ctx context.Context, session *subscraping.Session, randomApiKey subscraping.BasicAuth) (string, error) {
	creds := &zoomAuth{
		User: randomApiKey.Username,
		Pass: randomApiKey.Password,
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
func (z *ZoomEye) Name() string {
	return "zoomeye"
}

func (z *ZoomEye) SourceType() string {
	return subscraping.TYPE_API
}
