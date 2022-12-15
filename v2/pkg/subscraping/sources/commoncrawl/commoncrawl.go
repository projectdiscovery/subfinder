// Package commoncrawl logic
package commoncrawl

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const (
	indexURL     = "https://index.commoncrawl.org/collinfo.json"
	maxYearsBack = 5
)

var year = time.Now().Year()

type indexResponse struct {
	ID     string `json:"id"`
	APIURL string `json:"cdx-api"`
}

// CommonCrawl is the Source that handles access to the CommonCrawl data source.
type CommonCrawl struct {
	*subscraping.Source
}

func NewCommonCrawl() *CommonCrawl {
	return &CommonCrawl{Source: &subscraping.Source{Errors: 0, Results: 0}}
}

// Run function returns all subdomains found with the service
func (c *CommonCrawl) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			c.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		resp, err := session.SimpleGet(ctx, indexURL)
		if err != nil {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			c.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var indexes []indexResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&indexes)
		if err != nil {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			c.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		years := make([]string, 0)
		for i := 0; i < maxYearsBack; i++ {
			years = append(years, strconv.Itoa(year-i))
		}

		searchIndexes := make(map[string]string)
		for _, year := range years {
			for _, index := range indexes {
				if strings.Contains(index.ID, year) {
					if _, ok := searchIndexes[year]; !ok {
						searchIndexes[year] = index.APIURL
						break
					}
				}
			}
		}

		for _, apiURL := range searchIndexes {
			further := c.getSubdomains(ctx, apiURL, domain, session, results)
			if !further {
				break
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (c *CommonCrawl) Name() string {
	return "commoncrawl"
}

func (c *CommonCrawl) SourceType() string {
	return subscraping.TYPE_CRAWL
}

func (c *CommonCrawl) getSubdomains(ctx context.Context, searchURL, domain string, session *subscraping.Session, results chan subscraping.Result) bool {
	for {
		select {
		case <-ctx.Done():
			return false
		default:
			var headers = map[string]string{"Host": "index.commoncrawl.org"}
			resp, err := session.Get(ctx, fmt.Sprintf("%s?url=*.%s", searchURL, domain), "", headers)
			if err != nil {
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
				session.DiscardHTTPResponse(resp)
				return false
			}

			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" {
					continue
				}
				line, _ = url.QueryUnescape(line)
				subdomain := session.Extractor.FindString(line)
				if subdomain != "" {
					// fix for triple encoded URL
					subdomain = strings.ToLower(subdomain)
					subdomain = strings.TrimPrefix(subdomain, "25")
					subdomain = strings.TrimPrefix(subdomain, "2f")

					results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: subdomain}
				}
			}
			resp.Body.Close()
			return true
		}
	}
}
