package runner

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"io"
)

func loadFromFile(file string) ([]string, error) {
	chanItems, err := fileutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var items []string
	for item := range chanItems {
		item = preprocessDomain(item)
		if item == "" {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func preprocessDomain(s string) string {
	return stringsutil.NormalizeWithOptions(s,
		stringsutil.NormalizeOptions{
			StripComments: true,
			TrimCutset:    "\n\t\"'` ",
			Lowercase:     true,
		},
	)
}

func filterLinesByRange(r io.Reader, start, end int) (io.Reader, error) {
	scanner := bufio.NewScanner(r)
	var buffer bytes.Buffer

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber >= start && lineNumber <= end {
			buffer.WriteString(scanner.Text() + "\n")
		}
		if lineNumber > end {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if buffer.Len() == 0 {
		return nil, errors.New("incorrect file read boundaries")
	}

	if lineNumber < end {
		gologger.Info().Msgf("The provided upper bound (%d) is greater than the file size (%d). Scanning will continue to the end of the file.", end, lineNumber)
	}

	return &buffer, nil
}
