package dnsdb

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

type dnsdbResponse struct {
	Name string `json:"rrname"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	if session.Keys.DNSDB == "" {
		close(results)
	} else {
		headers := map[string]string{
			"X-API-KEY":    session.Keys.DNSDB,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}

		go func() {
			resp, err := session.Get(ctx, fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=1000000000000", domain), "", headers)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				close(results)
				return
			}

			// Check status code
			if resp.StatusCode != 200 {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("invalid status code received: %d", resp.StatusCode)}
				io.Copy(ioutil.Discard, resp.Body)
				resp.Body.Close()
				close(results)
				return
			}

			defer resp.Body.Close()
			// Get the response body
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				out := &dnsdbResponse{}
				err := json.Unmarshal([]byte(line), out)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					resp.Body.Close()
					close(results)
					return
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: strings.TrimSuffix(out.Name, ".")}
				out = nil
			}
			close(results)
		}()
	}
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "DNSDB"
}
