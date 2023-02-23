package hunter

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type hunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
}

type hunterData struct {
	InfoArr []infoArr `json:"arr"`
	Total   int       `json:"total"`
}

// Source is the passive scraping agent
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

		var pages = 1
		var pageSize = 100
		for currentPage := 1; currentPage <= pages; currentPage++ {
			// hunter api doc https://hunter.qianxin.com/home/helpCenter?r=5-1-2
			qbase64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("domain.suffix=\"%s\"", domain)))
			resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d&is_web=3", randomApiKey, qbase64, currentPage, pageSize))
			if err != nil && resp == nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var response hunterResp
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if response.Code == 401 || response.Code == 400 {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
				}
				return
			}
			if response.Code == 429 {
				gologger.Debug().Msgf("Hunter API  speed limit")
				currentPage -= 1
				time.Sleep(time.Second * 3)
				continue
			}
			if response.Data.Total > 0 {
				for _, hunterInfo := range response.Data.InfoArr {
					subdomain := hunterInfo.Domain
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				}
			}
			// api has a speed limit, so requires sleep.
			time.Sleep(time.Second * 3)
			pages = int(response.Data.Total/pageSize) + 1
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hunter"
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
