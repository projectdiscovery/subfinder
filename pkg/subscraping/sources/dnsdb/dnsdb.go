// Package dnsdb logic
package dnsdb

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		var resultCount uint64
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			stats.Results = int(resultCount)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		sourceName := s.Name()

		randomApiKey := subscraping.PickRandom(apiKeys, sourceName)
		if randomApiKey == "" {
			return
		}

		// Honor an optional per-source result limit (0 = no limit) so a single
		// domain can't drain an API quota by paginating to the end.
		maxResults := session.MaxResults

		headers := map[string]string{
			"X-API-KEY": randomApiKey,
			"Accept":    "application/x-ndjson",
		}

		stats.Requests++
		offsetMax, err := getMaxOffset(ctx, session, headers)
		if err != nil {
			results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
			stats.Errors++
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

			stats.Requests++
			resp, err := session.Get(ctx, url, "", headers)
			if err != nil {
				results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
				stats.Errors++
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
					stats.Errors++
					session.DiscardHTTPResponse(resp)
					return
				}

				var response safResponse
				err = jsoniter.Unmarshal(n, &response)
				if err != nil {
					results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
					stats.Errors++
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
							resultCount++
						}
						if maxResults > 0 && resultCount >= uint64(maxResults) {
							session.DiscardHTTPResponse(resp)
							return
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
				if offsetMax != 0 && resultCount <= offsetMax {
					// Reset done to false to get more results with an offset query parameter set to resultCount
					queryParams.Set("offset", strconv.FormatUint(resultCount, 10))
					continue
				}
			} else if respCond != "succeeded" {
				// DNSDB's terminating jsonl object's cond is not "limited" or succeeded" (#3), this is an error, notify the user.
				err = fmt.Errorf("%s terminated with condition: %s", sourceName, respCond)
				results <- subscraping.Result{Source: sourceName, Type: subscraping.Error, Error: err}
				stats.Errors++
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

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
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
