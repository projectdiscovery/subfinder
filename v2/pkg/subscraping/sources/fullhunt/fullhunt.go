package fullhunt

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

//fullHunt response
type fullHuntResponse struct {
	Hosts   []hostDetails `json:"hosts"`
	Message string        `json:"message"`
	Status  int           `json:"status"`
}

// hostDetails struct
type hostDetails struct {
	Host string `json:"host"`
}

// Source is the passive scraping agent
type Source struct{}

func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)
		
		resp, err := session.Get(ctx, fmt.Sprintf("https://fullhunt.io/api/v1/domain/%s/details", domain), "", map[string]string{"X-API-KEY": session.Keys.FullHunt})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response fullHuntResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		var x = ""
		for _, record := range response.Hosts {
			x = fmt.Sprintf("\"%s,\"%s\"", x, record.Host)
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: record.Host}
		}
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "fullhunt"
}
