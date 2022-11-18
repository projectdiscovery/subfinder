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

// ReconCloud is the Source that handles access to the ReconCloud data source.
type ReconCloud struct {
	*subscraping.Source
}

func NewReconCloud() *ReconCloud {
	return &ReconCloud{Source: &subscraping.Source{}}
}

// Run function returns all subdomains found with the service
func (r *ReconCloud) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://recon.cloud/api/search?domain=%s", domain))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response reconCloudResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: r.Name(), Type: subscraping.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if len(response.CloudAssetsList) > 0 {
			for _, cloudAsset := range response.CloudAssetsList {
				results <- subscraping.Result{Source: r.Name(), Type: subscraping.Subdomain, Value: cloudAsset.Domain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (r *ReconCloud) Name() string {
	return "reconcloud"
}

func (r *ReconCloud) IsDefault() bool {
	return true
}

func (r *ReconCloud) HasRecursiveSupport() bool {
	return true
}

func (r *ReconCloud) SourceType() string {
	return subscraping.TYPE_API
}
