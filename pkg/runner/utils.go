package runner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

// UploadToChaosTimeoutNano timeout to upload to Chaos in nanoseconds
const UploadToChaosTimeoutNano = 600

// JSONResult contains the result for a host in JSON format
type JSONResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

func (r *Runner) UploadToChaos(reader io.Reader) error {
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

	request, err := http.NewRequest("POST", "https://dns.projectdiscovery.io/dns/add", reader)
	if err != nil {
		return errors.Wrap(err, "could not create request")
	}
	request.Header.Set("Authorization", r.options.YAMLConfig.GetKeys().Chaos)

	resp, err := httpClient.Do(request)
	if err != nil {
		return errors.Wrap(err, "could not make request")
	}
	defer func() {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code received: %d", resp.StatusCode)
	}
	return nil
}

// WriteHostOutput writes the output list of subdomain to an io.Writer
func WriteHostOutput(results map[string]struct{}, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for host := range results {
		sb.WriteString(host)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteHostOutputNoWildcard writes the output list of subdomain with nW flag to an io.Writer
func WriteHostOutputNoWildcard(results map[string]string, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for host := range results {
		sb.WriteString(host)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

// WriteJSONOutput writes the output list of subdomain in JSON to an io.Writer
func WriteJSONOutput(results map[string]string, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	data := JSONResult{}

	for host, ip := range results {
		data.Host = host
		data.IP = ip

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteHostIPOutput writes the output list of subdomain to an io.Writer
func WriteHostIPOutput(results map[string]string, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for host, ip := range results {
		sb.WriteString(host)
		sb.WriteString(",")
		sb.WriteString(ip)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}
