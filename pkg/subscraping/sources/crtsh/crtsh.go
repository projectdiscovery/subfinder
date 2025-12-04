// Package crtsh logic
package crtsh

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	// postgres driver
	_ "github.com/lib/pq"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	contextutil "github.com/projectdiscovery/utils/context"
)

type subdomain struct {
	ID        int    `json:"id"`
	NameValue string `json:"name_value"`
}

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
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

		count := s.getSubdomainsFromSQL(ctx, domain, session, results)
		if count > 0 {
			return
		}
		_ = s.getSubdomainsFromHTTP(ctx, domain, session, results)
	}()

	return results
}

func (s *Source) getSubdomainsFromSQL(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) int {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		return 0
	}

	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			gologger.Warning().Msgf("Could not close database connection: %s\n", closeErr)
		}
	}()

	limitClause := ""
	if all, ok := ctx.Value(contextutil.ContextArg("All")).(contextutil.ContextArg); ok {
		if allBool, err := strconv.ParseBool(string(all)); err == nil && !allBool {
			limitClause = "LIMIT 10000"
		}
	}

	query := fmt.Sprintf(`WITH ci AS (
				SELECT min(sub.CERTIFICATE_ID) ID,
					min(sub.ISSUER_CA_ID) ISSUER_CA_ID,
					array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
					x509_commonName(sub.CERTIFICATE) COMMON_NAME,
					x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,
					x509_notAfter(sub.CERTIFICATE) NOT_AFTER,
					encode(x509_serialNumber(sub.CERTIFICATE), 'hex') SERIAL_NUMBER
					FROM (SELECT *
							FROM certificate_and_identities cai
							WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
								AND cai.NAME_VALUE ILIKE ('%%' || $1 || '%%')
								%s
						) sub
					GROUP BY sub.CERTIFICATE
			)
			SELECT array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE
				FROM ci
						LEFT JOIN LATERAL (
							SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
								FROM ct_log_entry ctle
								WHERE ctle.CERTIFICATE_ID = ci.ID
						) le ON TRUE,
					ca
				WHERE ci.ISSUER_CA_ID = ca.ID
				ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;`, limitClause)
	rows, err := db.QueryContext(ctx, query, domain)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		return 0
	}
	if err := rows.Err(); err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		return 0
	}

	var count int
	var data string
	for rows.Next() {
		select {
		case <-ctx.Done():
			return count
		default:
		}
		err := rows.Scan(&data)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return count
		}

		count++
		for subdomain := range strings.SplitSeq(data, "\n") {
			for _, value := range session.Extractor.Extract(subdomain) {
				if value != "" {
					select {
					case <-ctx.Done():
						return count
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
						s.results++
					}
				}
			}
		}
	}
	return count
}

func (s *Source) getSubdomainsFromHTTP(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) bool {
	resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return false
	}

	var subdomains []subdomain
	err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return false
	}

	session.DiscardHTTPResponse(resp)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return true
		default:
		}
		for sub := range strings.SplitSeq(subdomain.NameValue, "\n") {
			for _, value := range session.Extractor.Extract(sub) {
				if value != "" {
					select {
					case <-ctx.Done():
						return true
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
						s.results++
					}
				}
			}
		}
	}

	return true
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "crtsh"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
	}
}
