package runner

import (
	"strings"
	"unicode"

	fileutil "github.com/projectdiscovery/utils/file"
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

func trim(s string) string {
	return strings.Trim(s, "\n\t\"'` ")
}

func stripComment(s string) string {
	if cut := strings.IndexAny(s, "#"); cut >= 0 {
		return strings.TrimRightFunc(s[:cut], unicode.IsSpace)
	}
	return s
}

func preprocessDomain(s string) string {
	return strings.ToLower(trim(stripComment(s)))
}
