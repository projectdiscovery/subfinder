package subscraping

import (
	"regexp"
	"strings"
)

// RegexSubdomainExtractor is a concrete implementation of the SubdomainExtractor interface, using regex for extraction.
type RegexSubdomainExtractor struct {
	extractor *regexp.Regexp
}

// NewSubdomainExtractor creates a new regular expression to extract
// subdomains from text based on the given domain.
func NewSubdomainExtractor(domain string) (*RegexSubdomainExtractor, error) {
	// QuoteMeta escapes the domain so its dots (and any other metacharacters)
	// are matched literally. Without this, "example.com" also matches text like
	// "exampleXcom" because "." means "any character" in a regex.
	extractor, err := regexp.Compile(`(?i)[a-zA-Z0-9\*_.-]+\.` + regexp.QuoteMeta(domain))
	if err != nil {
		return nil, err
	}
	return &RegexSubdomainExtractor{extractor: extractor}, nil
}

// Extract implements the SubdomainExtractor interface, using the regex to find subdomains in the given text.
func (re *RegexSubdomainExtractor) Extract(text string) []string {
	indices := re.extractor.FindAllStringIndex(text, -1)
	matches := make([]string, 0, len(indices))
	for _, idx := range indices {
		// Skip matches that are only a prefix of a longer hostname, e.g.
		// "foo.example.com" found inside "foo.example.com.evil.org": these end at
		// the target domain but the host actually belongs to a different apex.
		if hostnameContinues(text, idx[1]) {
			continue
		}
		matches = append(matches, strings.ToLower(text[idx[0]:idx[1]]))
	}
	return matches
}

// hostnameContinues reports whether the hostname at the given end index extends
// further in text, i.e. the match is not a complete host. A single trailing dot
// (the FQDN form "host.") is tolerated, but an additional label such as the
// ".evil.org" in "foo.example.com.evil.org" is treated as a continuation.
func hostnameContinues(text string, end int) bool {
	if end >= len(text) {
		return false
	}
	b := text[end]
	if isLabelByte(b) {
		return true
	}
	if b == '.' {
		return end+1 < len(text) && isLabelStart(text[end+1])
	}
	return false
}

func isLabelByte(b byte) bool {
	return isLabelStart(b) || b == '-' || b == '_'
}

func isLabelStart(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}
