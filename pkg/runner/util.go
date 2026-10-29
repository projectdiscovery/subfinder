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
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	// Drop the root label of an FQDN ("example.com.") so the enumerator's
	// suffix check matches the normalized hosts reported by sources.
	return strings.TrimSuffix(s, ".")
}

// normalizeSubdomain normalizes a subdomain reported by a source. Sources
// reporting hosts verbatim keep the FQDN trailing dot or mixed case, which
// the domain suffix check in the enumerator would otherwise reject.
func normalizeSubdomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(s), ".")
}

// isValidHostname reports whether s is a DNS host name: at most 253 bytes,
// labels of 1 to 63 bytes from a-z, 0-9, '-' and '_'. s must be normalized
// (lowercase, no trailing dot). Whitespace, control characters and any other
// byte are rejected.
func isValidHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// sourceHost returns the host part of a source value: a URL scheme and
// everything from the first "/" are removed, so a path never joins the name.
func sourceHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
