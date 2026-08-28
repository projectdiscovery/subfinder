package runner

import (
	"strings"

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
	s = stringsutil.NormalizeWithOptions(s,
		stringsutil.NormalizeOptions{
			StripComments: true,
			TrimCutset:    "\n\t\"'` ",
			Lowercase:     true,
		},
	)
	// Strip a leading http(s):// scheme and any path/query/fragment so entries
	// pasted as URLs (e.g. "https://8.8.8.8/foo?a=b") normalize to a bare host
	// usable by dnsx instead of silently failing.
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if atIdx := strings.LastIndex(s, "@"); atIdx != -1 {
		// Only strip userinfo if @ is before path delimiter
		if slashIdx := strings.Index(s, "/"); slashIdx == -1 || atIdx < slashIdx {
			s = s[atIdx+1:]
		}
	}
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	return s
}
