package runner

import (
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
