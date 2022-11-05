// Package reconcloud logic
package reconcloud

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type reconCloudResponse struct {
	MsgType         string            `json:"msg_type"`
	RequestID       string            `json:"request_id"`
	OnCache         bool              `json:"on_cache"`
	Step            string            `json:"step"`
	CloudAssetsList []cloudAssetsList `json:"cloud_assets_list"`
}

type cloudAssetsList struct {
	Key           string `json:"key"`
	Domain        string `json:"domain"`
	CloudProvider string `json:"cloud_provider"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://recon.cloud/api/search?domain=%s", domain))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response reconCloudResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if len(response.CloudAssetsList) > 0 {
			for _, cloudAsset := range response.CloudAssetsList {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: cloudAsset.Domain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "reconcloud"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) NeedsKey() bool {
	return false
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}
