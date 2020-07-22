package crtsh

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"strings"

	// postgres driver
	_ "github.com/lib/pq"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		found := s.getSubdomainsFromSQL(domain, results)
		if found {
			close(results)
			return
		}
		_ = s.getSubdomainsFromHTTP(ctx, domain, session, results)
		close(results)
	}()

	return results
}

func (s *Source) getSubdomainsFromSQL(domain string, results chan subscraping.Result) bool {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return false
	}

	pattern := "%." + domain
	rows, err := db.Query(`SELECT DISTINCT ci.NAME_VALUE as domain
	FROM certificate_identity ci
	WHERE reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))
	ORDER BY ci.NAME_VALUE`, pattern)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		return false
	}

	var data string
	// Parse all the rows getting subdomains
	for rows.Next() {
		err := rows.Scan(&data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return false
		}
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: data}
	}
	return true
}

func (s *Source) getSubdomainsFromHTTP(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) bool {
	resp, err := session.NormalGetWithContext(ctx, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		session.DiscardHTTPResponse(resp)
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		resp.Body.Close()
		return false
	}
	resp.Body.Close()

	// Also replace all newlines
	src := strings.ReplaceAll(string(body), "\\n", " ")

	for _, subdomain := range session.Extractor.FindAllString(src, -1) {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
	}
	return true
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "crtsh"
}
