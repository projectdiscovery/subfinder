// Package dnsdb logic
package dnsdb

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

const urlBase string = "https://api.dnsdb.info/dnsdb/v2"

type rateResponse struct {
	Rate rate
}

type rate struct {
	OffsetMax json.Number `json:"offset_max"`
}

type safResponse struct {
	Condition string   `json:"cond"`
	Obj       dnsdbObj `json:"obj"`
	Msg       string   `json:"msg"`
}

type dnsdbObj struct {
	Name string `json:"rrname"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   uint64
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

		sourceName := s.Name()

		randomApiKey := subscraping.PickRandom(s.apiKeys, sourceName)
		if randomApiKey == "" {
			return
		}

		headers := map[string]string{
			"X-API-KEY": randomApiKey,
			"Accept":    "application/x-ndjson",
		}

		offsetMax, err := getMaxOffset(ctx, session, headers)
		if err != nil {
			results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		path := fmt.Sprintf("lookup/rrset/name/*.%s", domain)
		urlTemplate := fmt.Sprintf("%s/%s?", urlBase, path)
		queryParams := url.Values{}
		// ?limit=0 means DNSDB will return the maximum number of results allowed.
		queryParams.Add("limit", "0")
		queryParams.Add("swclient", "subfinder")

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			url := urlTemplate + queryParams.Encode()

			resp, err := session.Get(ctx, url, "", headers)
			if err != nil {
				results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var respCond string
			reader := bufio.NewReader(resp.Body)
			for {
				select {
				case <-ctx.Done():
					session.DiscardHTTPResponse(resp)
					return
				default:
				}
				n, err := reader.ReadBytes('\n')
				if err == io.EOF {
					break
				} else if err != nil {
					results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
					return
				}

				var response safResponse
				err = jsoniter.Unmarshal(n, &response)
				if err != nil {
					results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
					return
				}

				respCond = response.Condition
				if respCond == "" || respCond == "ongoing" {
					if response.Obj.Name != "" {
						select {
						case <-ctx.Done():
							session.DiscardHTTPResponse(resp)
							return
						case results <- subscraping.Result{Source: sourceName, Type: subscraping.Subdomain, Value: strings.TrimSuffix(response.Obj.Name, ".")}:
							s.results++
						}
					}
				} else if respCond != "begin" {
					break
				}
			}

			// Check the terminating jsonl object's condition. There are 3 possible scenarios:
			// 1. "limited" - There are more results available, make another query with an offset
			// 2. "succeeded" - The query completed successfully and all results were sent.
			// 3. anything else - This is an error and should be reported to the user. The user can then decide to use the results up to this
			// point or discard and retry.
			if respCond == "limited" {
				if offsetMax != 0 && s.results <= offsetMax {
					// Reset done to false to get more results with an offset query parameter set to s.results
					queryParams.Set("offset", strconv.FormatUint(s.results, 10))
					continue
				}
			} else if respCond != "succeeded" {
				// DNSDB's terminating jsonl object's cond is not "limited" or succeeded" (#3), this is an error, notify the user.
				err = fmt.Errorf("%s terminated with condition: %s", sourceName, respCond)
				results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
				s.errors++
			}

			session.DiscardHTTPResponse(resp)
			break
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "dnsdb"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return true
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
		Results:   int(s.results),
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}

func getMaxOffset(ctx context.Context, session *subscraping.Session, headers map[string]string) (uint64, error) {
	var offsetMax uint64
	url := fmt.Sprintf("%s/rate_limit", urlBase)
	resp, err := session.Get(ctx, url, "", headers)
	defer session.DiscardHTTPResponse(resp)
	if err != nil {
		return offsetMax, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return offsetMax, err
	}
	var rateResp rateResponse
	err = jsoniter.Unmarshal(data, &rateResp)
	if err != nil {
		return offsetMax, err
	}
	// if the OffsetMax is "n/a" then the ?offset= query parameter is not allowed
	if rateResp.Rate.OffsetMax.String() != "n/a" {
		offsetMax, err = strconv.ParseUint(rateResp.Rate.OffsetMax.String(), 10, 64)
		if err != nil {
			return offsetMax, err
		}
	}

	return offsetMax, nil
}
