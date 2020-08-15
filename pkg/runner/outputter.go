package runner

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

type jsonResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

// OutPutter outputs content to writers.
type OutPutter struct{}

func (o *OutPutter) createFile(filename, outputDirectory string, json, appendtoFile bool) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	absFilePath := filename

	if outputDirectory != "" {
		if _, err := os.Stat(outputDirectory); os.IsNotExist(err) {
			err := os.MkdirAll(outputDirectory, os.ModePerm)
			if err != nil {
				return nil, err
			}
		}
		absFilePath = path.Join(outputDirectory, filename)
	}

	if filepath.Ext(absFilePath) == "" {
		if json {
			absFilePath += ".json"
		} else {
			absFilePath += ".txt"
		}
	}

	var file *os.File
	var err error
	if appendtoFile {
		file, err = os.OpenFile(absFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(absFilePath)
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// WriteHostIP writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteHostIP(results map[string]string, writer io.Writer) error {
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

// WriteJSON writes the output list of subdomain in JSON to an io.Writer
func (o *OutPutter) WriteJSON(results map[string]string, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	data := jsonResult{}

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

// WriteHostNoWildcard writes the output list of subdomain with nW flag to an io.Writer
func (o *OutPutter) WriteHostNoWildcard(results map[string]string, writer io.Writer) error {
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

// WriteHost writes the output list of subdomain to an io.Writer
func (o *OutPutter) WriteHost(results map[string]struct{}, writer io.Writer) error {
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
