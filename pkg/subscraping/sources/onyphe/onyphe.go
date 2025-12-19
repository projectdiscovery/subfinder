// Package onyphe logic
package onyphe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type OnypheResponse struct {
	Error    int      `json:"error"`
	Results  []Result `json:"results"`
	Page     int      `json:"page"`
	PageSize int      `json:"page_size"`
	Total    int      `json:"total"`
	MaxPage  int      `json:"max_page"`
}

type Result struct {
	Subdomains []string `json:"subdomains"`
	Hostname   string   `json:"hostname"`
	Forward    string   `json:"forward"`
	Reverse    string   `json:"reverse"`
	Host       string   `json:"host"`
	Domain     string   `json:"domain"`
}

type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
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
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		headers := map[string]string{"Content-Type": "application/json", "Authorization": "bearer " + randomApiKey}

		page := 1
		pageSize := 1000

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			var resp *http.Response
			var err error

			urlWithQuery := fmt.Sprintf("https://www.onyphe.io/api/v2/search/?q=%s&page=%d&size=%d",
				url.QueryEscape("category:resolver domain:"+domain), page, pageSize)
			resp, err = session.Get(ctx, urlWithQuery, "", headers)

			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var respOnyphe OnypheResponse
			err = json.NewDecoder(resp.Body).Decode(&respOnyphe)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			session.DiscardHTTPResponse(resp)

			for _, record := range respOnyphe.Results {
				select {
				case <-ctx.Done():
					return
				default:
				}
				for _, subdomain := range record.Subdomains {
					if subdomain != "" {
						results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
						s.results++
					}
				}

				if record.Hostname != "" {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Hostname}
					s.results++
				}

				if record.Forward != "" {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Forward}
					s.results++
				}

				if record.Reverse != "" {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Reverse}
					s.results++
				}
			}

			if len(respOnyphe.Results) == 0 || page >= respOnyphe.MaxPage {
				break
			}

			page++

		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "onyphe"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}

type OnypheResponseRaw struct {
	Error    int             `json:"error"`
	Results  []Result        `json:"results"`
	Page     json.RawMessage `json:"page"`
	PageSize json.RawMessage `json:"page_size"`
	Total    json.RawMessage `json:"total"`
	MaxPage  json.RawMessage `json:"max_page"`
}

func (o *OnypheResponse) UnmarshalJSON(data []byte) error {
	var raw OnypheResponseRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	o.Error = raw.Error
	o.Results = raw.Results

	if pageStr := string(raw.Page); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil {
			o.Page = page
		} else {
			var pageStrQuoted string
			if err := json.Unmarshal(raw.Page, &pageStrQuoted); err == nil {
				if page, err := strconv.Atoi(pageStrQuoted); err == nil {
					o.Page = page
				}
			}
		}
	}

	if pageSizeStr := string(raw.PageSize); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil {
			o.PageSize = pageSize
		} else {
			var pageSizeStrQuoted string
			if err := json.Unmarshal(raw.PageSize, &pageSizeStrQuoted); err == nil {
				if pageSize, err := strconv.Atoi(pageSizeStrQuoted); err == nil {
					o.PageSize = pageSize
				}
			}
		}
	}

	if totalStr := string(raw.Total); totalStr != "" {
		if total, err := strconv.Atoi(totalStr); err == nil {
			o.Total = total
		} else {
			var totalStrQuoted string
			if err := json.Unmarshal(raw.Total, &totalStrQuoted); err == nil {
				if total, err := strconv.Atoi(totalStrQuoted); err == nil {
					o.Total = total
				}
			}
		}
	}

	if maxPageStr := string(raw.MaxPage); maxPageStr != "" {
		if maxPage, err := strconv.Atoi(maxPageStr); err == nil {
			o.MaxPage = maxPage
		} else {
			var maxPageStrQuoted string
			if err := json.Unmarshal(raw.MaxPage, &maxPageStrQuoted); err == nil {
				if maxPage, err := strconv.Atoi(maxPageStrQuoted); err == nil {
					o.MaxPage = maxPage
				}
			}
		}
	}

	return nil
}

type ResultRaw struct {
	Subdomains json.RawMessage `json:"subdomains"`
	Hostname   json.RawMessage `json:"hostname"`
	Forward    json.RawMessage `json:"forward"`
	Reverse    json.RawMessage `json:"reverse"`
	Host       json.RawMessage `json:"host"`
	Domain     json.RawMessage `json:"domain"`
}

func (r *Result) UnmarshalJSON(data []byte) error {
	var raw ResultRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var subdomains []string
	if err := json.Unmarshal(raw.Subdomains, &subdomains); err == nil {
		r.Subdomains = subdomains
	} else {
		var subdomainStr string
		if err := json.Unmarshal(raw.Subdomains, &subdomainStr); err == nil {
			r.Subdomains = []string{subdomainStr}
		}
	}

	if len(raw.Hostname) > 0 {
		var hostnameStr string
		if err := json.Unmarshal(raw.Hostname, &hostnameStr); err == nil {
			r.Hostname = hostnameStr
		} else {
			var hostnameArr []string
			if err := json.Unmarshal(raw.Hostname, &hostnameArr); err == nil && len(hostnameArr) > 0 {
				r.Hostname = hostnameArr[0]
			}
		}
	}

	if len(raw.Forward) > 0 {
		_ = json.Unmarshal(raw.Forward, &r.Forward)
	}

	if len(raw.Reverse) > 0 {
		_ = json.Unmarshal(raw.Reverse, &r.Reverse)
	}

	if len(raw.Host) > 0 {
		var hostStr string
		if err := json.Unmarshal(raw.Host, &hostStr); err == nil {
			r.Host = hostStr
		} else {
			var hostArr []string
			if err := json.Unmarshal(raw.Host, &hostArr); err == nil && len(hostArr) > 0 {
				r.Host = hostArr[0]
			}
		}
	}

	if len(raw.Domain) > 0 {
		var domainStr string
		if err := json.Unmarshal(raw.Domain, &domainStr); err == nil {
			r.Domain = domainStr
		} else {
			var domainArr []string
			if err := json.Unmarshal(raw.Domain, &domainArr); err == nil && len(domainArr) > 0 {
				r.Domain = domainArr[0]
			}
		}
	}

	return nil
}
