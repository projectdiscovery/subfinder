package facebook

import (
	"errors"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/subfinder/subfinder/pkg/subscraping"
)

type authResponse struct {
	AccessToken string `json:"access_token"`
}

type response struct {
	Data []struct {
		Domains []string `json:"domains"`
	} `json:"data"`

	Paging struct {
		Next string `json:"next"`
	} `json:"paging"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.FacebookAppID == "" || session.Keys.FacebookAppSecret == "" {
			close(results)
			return
		}

		resp, err := session.NormalGet(fmt.Sprintf("https://graph.facebook.com/oauth/access_token?client_id=%s&client_secret=%s&grant_type=client_credentials", session.Keys.FacebookAppID, session.Keys.FacebookAppSecret))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		auth := authResponse{}
		err = jsoniter.NewDecoder(resp.Body).Decode(&auth)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}

		if auth.AccessToken == "" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: errors.New("no access token in Facebook API response")}
			close(results)
			return
		}

		fetchURL := fmt.Sprintf("https://graph.facebook.com/certificates?fields=domains&access_token=%s&query=*.%s", auth.AccessToken, domain)

		wrapper := new(response)
		for {
			resp, err := session.NormalGet(fetchURL)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}

			err = jsoniter.NewDecoder(resp.Body).Decode(&wrapper)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}

			for _, data := range wrapper.Data {
				for _, d := range data.Domains {
					d := strings.TrimPrefix(strings.ToLower(d), "*.")

					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: d}
				}
			}

			fetchURL = wrapper.Paging.Next
			if fetchURL == "" {
				break
			}
		}
		close(results)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "facebook"
}
