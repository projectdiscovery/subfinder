package chinaz

// chinaz  http://my.chinaz.com/ChinazAPI/DataCenter/MyDataApi
import (
	"context"
	"fmt"
	"io"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Chinaz is the KeyApiSource that handles access to the Chinaz data source.
type Chinaz struct {
	*subscraping.KeyApiSource
}

func NewChinaz() *Chinaz {
	return &Chinaz{KeyApiSource: &subscraping.KeyApiSource{}}
}

// Run function returns all subdomains found with the service
func (c *Chinaz) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		randomApiKey := subscraping.PickRandom(c.ApiKeys(), c.Name())
		if randomApiKey == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://apidatav2.chinaz.com/single/alexa?key=%s&domain=%s", randomApiKey, domain))
		if err != nil {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
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
				results <- subscraping.Result{Source: c.Name(), Type: subscraping.Subdomain, Value: subdomain}
			}
		} else {
			results <- subscraping.Result{Source: c.Name(), Type: subscraping.Error, Error: err}
			return
		}
	}()

	return results
}

// Name returns the name of the source
func (c *Chinaz) Name() string {
	return "chinaz"
}

func (c *Chinaz) IsDefault() bool {
	return true
}

func (c *Chinaz) SourceType() string {
	return subscraping.TYPE_API
}
