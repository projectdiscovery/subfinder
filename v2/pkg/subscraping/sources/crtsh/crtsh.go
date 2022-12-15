// Package crtsh logic
package crtsh

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	// postgres driver
	_ "github.com/lib/pq"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type subdomain struct {
	ID        int    `json:"id"`
	NameValue string `json:"name_value"`
}

// Crtsh is the Source that handles access to the Crtsh data source.
type Crtsh struct {
	*subscraping.Source
}

func NewCrtsh() *Crtsh {
	return &Crtsh{Source: &subscraping.Source{Errors: 0, Results: 0}}
}

// Run function returns all subdomains found with the service
func (c *Crtsh) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			c.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		count := c.getSubdomainsFromSQL(domain, session, results)
		if count > 0 {
			return
		}
		_ = c.getSubdomainsFromHTTP(ctx, domain, session, results)
	}()

	return results
}

func (c *Crtsh) getSubdomainsFromSQL(domain string, session *subscraping.Session, results chan subscraping.Result) int {
	db, err := sql.Open("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable binary_parameters=yes")
	if err != nil {
		results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
		c.Errors++
		return 0
	}

	defer db.Close()

	query := `WITH ci AS (
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
								AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')
							LIMIT 10000
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
				ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;`
	rows, err := db.Query(query, domain)
	if err != nil {
		results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
		c.Errors++
		return 0
	}
	if err := rows.Err(); err != nil {
		results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
		c.Errors++
		return 0
	}

	var count int
	var data string
	// Parse all the rows getting subdomains
	for rows.Next() {
		err := rows.Scan(&data)
		if err != nil {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			c.Errors++
			return count
		}

		count++
		for _, subdomain := range strings.Split(data, "\n") {
			subdomain := session.Extractor.FindString(subdomain)
			if subdomain != "" {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: subdomain}
				c.Results++
			}
		}
	}
	return count
}

func (c *Crtsh) getSubdomainsFromHTTP(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) bool {
	resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil {
		results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
		c.Errors++
		session.DiscardHTTPResponse(resp)
		return false
	}

	var subdomains []subdomain
	err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
	if err != nil {
		results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
		c.Errors++
		resp.Body.Close()
		return false
	}

	resp.Body.Close()

	for _, subdomain := range subdomains {
		for _, sub := range strings.Split(subdomain.NameValue, "\n") {
			sub = session.Extractor.FindString(sub)
			if sub != "" {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: sub}
			}
			c.Results++
		}
	}

	return true
}

// Name returns the name of the source
func (c *Crtsh) Name() string {
	return "crtsh"
}

func (c *Crtsh) IsDefault() bool {
	return true
}

func (c *Crtsh) HasRecursiveSupport() bool {
	return true
}

func (c *Crtsh) SourceType() string {
	return subscraping.TYPE_CERT
}
