package chinaz

// chinaz  http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi
import (
	"context"
	"fmt"
	"io"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	startTime := time.Now()

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://apidatav2.chinaz.com/single/alexa?key=%s&domain=%s", randomApiKey, domain))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := io.ReadAll(resp.Body)

		resp.Body.Close()

		SubdomainList := jsoniter.Get(body, "Result").Get("ContributingSubdomainList")

		if SubdomainList.ToBool() {
			_data := []byte(SubdomainList.ToString())
			for i := 0; i < SubdomainList.Size(); i++ {
				subdomain := jsoniter.Get(_data, i, "DataUrl").ToString()
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		} else {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}
		s.timeTaken = time.Since(startTime)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "chinaz"
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

func (s *Source) TimeTaken() time.Duration {
	return s.timeTaken
}
