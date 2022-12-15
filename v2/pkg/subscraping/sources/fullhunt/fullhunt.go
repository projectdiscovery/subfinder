package fullhunt

import (
	"context"
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// fullhunt response
type fullHuntResponse struct {
	Hosts   []string `json:"hosts"`
	Message string   `json:"message"`
	Status  int      `json:"status"`
}

// FullHunt is the KeyApiSource that handles access to the FullHunt data source.
type FullHunt struct {
	*subscraping.KeyApiSource
}

func NewFullHunt() *FullHunt {
	return &FullHunt{
		KeyApiSource: &subscraping.KeyApiSource{
			Source: &subscraping.Source{Errors: 0, Results: 0},
		},
	}
}

func (f *FullHunt) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer func(startTime time.Time) {
			f.TimeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(f.ApiKeys(), f.Name())
		if randomApiKey == "" {
			f.Skipped = true
			return
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/subdomains", domain), "", map[string]string{"X-API-KEY": randomApiKey})
		if err != nil {
			results <- subscraping.Result{Source: f.Name(), Type: subscraping.Error, Error: err}
			f.Errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response fullHuntResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: f.Name(), Type: subscraping.Error, Error: err}
			f.Errors++
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		for _, record := range response.Hosts {
			results <- subscraping.Result{Source: f.Name(), Type: subscraping.Subdomain, Value: record}
			f.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (f *FullHunt) Name() string {
	return "fullhunt"
}

func (f *FullHunt) IsDefault() bool {
	return true
}

func (f *FullHunt) SourceType() string {
	return subscraping.TYPE_API
}
