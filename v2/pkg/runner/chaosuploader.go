package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

// UploadToChaosTimeoutNano timeout to upload to Chaos in nanoseconds
const UploadToChaosTimeoutNano = 600

// UploadToChaos upload new data to Chaos dataset
func (r *Runner) UploadToChaos(ctx context.Context, reader io.Reader) error {
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			MaxIdleConns:        100,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(UploadToChaosTimeoutNano) * time.Second, // 10 minutes - uploads may take long
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://dns.projectdiscovery.io/dns/add", reader)
	if err != nil {
		return errors.Wrap(err, "could not create request")
	}
	request.Header.Set("Authorization", r.options.YAMLConfig.GetKeys().Chaos)

	resp, err := httpClient.Do(request)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	defer func() {
		_, err := io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			gologger.Warningf("Could not discard response body: %s\n", err)
			return
		}
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code received: %d", resp.StatusCode)
	}
	return nil
}
