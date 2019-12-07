package runner

import (
	"bufio"
	"io"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

// JSONResult contains the result for a host in JSON format
type JSONResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
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
