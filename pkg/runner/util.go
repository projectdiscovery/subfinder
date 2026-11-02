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
	return strings.TrimSuffix(strings.TrimSpace(strings.ToLower(s)), ".")
}

// isValidSubdomain reports whether s is a valid DNS hostname under RFC 1123 / RFC 952.
func isValidSubdomain(s string) bool {
	// Domain names must be between 1 and 253 octets.
	if len(s) == 0 || len(s) > 253 {
		return false
	}

	labels := strings.Split(s, ".")
	for _, label := range labels {
		// Each label must be between 1 and 63 octets.
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// Labels cannot begin or end with a hyphen.
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		// Characters must be alphanumeric, hyphen, or underscore (used in service/DKIM/DMARC records).
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// sourceSubdomain returns the candidate subdomain in a normalized source
// value, before the domain and syntax checks. The root dot of a URL host is
// trimmed here; a bare value was already trimmed once by normalizeSubdomain,
// and trimming it again would accept "foo.example.com..".
func sourceSubdomain(value string) string {
	host := sourceHost(value)
	if host != value {
		host = normalizeSubdomain(host)
	}
	return replacer.Replace(host)
}

// sourceHost returns the host part of a source value: a URL scheme and
// everything from the first "/", "?" or "#" are removed, so a path, query or
// fragment never joins the name.
func sourceHost(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
