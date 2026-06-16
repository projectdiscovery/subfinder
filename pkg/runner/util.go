package runner

import (
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

func loadFromFile(file string) ([]string, error) {
	var items []string
	for item, err := range fileutil.Lines(file) {
		if err != nil {
			return nil, err
		}
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
