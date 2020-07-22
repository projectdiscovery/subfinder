package zoomeye

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
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
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		if session.Keys.ZoomEyeUsername == "" || session.Keys.ZoomEyePassword == "" {
			close(results)
			return
		}
		jwt, err := doLogin(session)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			close(results)
			return
		}
		// check if jwt is null
		if jwt == "" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: errors.New("could not log into zoomeye")}
			close(results)
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
					session.DiscardHTTPResponse(resp)
				}
				close(results)
				return
			}

			defer resp.Body.Close()
			res := &zoomeyeResults{}
			err = json.NewDecoder(resp.Body).Decode(res)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				close(results)
				return
			}
			resp.Body.Close()
			for _, r := range res.Matches {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: r.Site}
				for _, domain := range r.Domains {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: domain}
				}
			}
			currentPage++
		}
		close(results)
	}()

	return results
}

// doLogin performs authentication on the ZoomEye API
func doLogin(session *subscraping.Session) (string, error) {
	creds := &zoomAuth{
		User: session.Keys.ZoomEyeUsername,
		Pass: session.Keys.ZoomEyePassword,
	}
	body, err := json.Marshal(&creds)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", "https://api.zoomeye.org/user/login", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")
	resp, err := session.Client.Do(req)
	if err != nil {
		return "", err
	}
	// if not 200, bad credentials
	if resp.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		return "", fmt.Errorf("login failed, non-200 response from zoomeye")
	}

	defer resp.Body.Close()
	login := &loginResp{}
	err = json.NewDecoder(resp.Body).Decode(login)
	if err != nil {
		return "", err
	}
	return login.JWT, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeye"
}
