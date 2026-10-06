package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreprocessDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare domain", "example.com", "example.com"},
		{"uppercase", "Example.COM", "example.com"},
		{"https scheme", "https://example.com", "example.com"},
		{"http scheme", "http://example.com", "example.com"},
		{"uppercase scheme and path", "HTTPS://Example.com/Path", "example.com"},
		{"scheme and path", "https://example.com/path/to", "example.com"},
		{"scheme and query", "http://example.com?a=b", "example.com"},
		{"scheme and fragment", "https://example.com#frag", "example.com"},
		{"path only", "example.com/foo", "example.com"},
		{"query only", "example.com?x=1", "example.com"},
		{"trailing slash", "example.com/", "example.com"},
		{"ip with scheme", "https://8.8.8.8", "8.8.8.8"},
		{"resolver host port kept", "8.8.8.8:53", "8.8.8.8:53"},
		{"wildcard kept", "*.example.com", "*.example.com"},
		{"quoted and spaced", "  \"example.com\" ", "example.com"},
		{"comment line", "# a comment", ""},
		{"inline comment", "example.com # note", "example.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := preprocessDomain(tt.in); got != tt.want {
				t.Fatalf("preprocessDomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeSubdomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare subdomain", "www.example.com", "www.example.com"},
		{"trailing dot", "www.example.com.", "www.example.com"},
		{"uppercase", "WWW.Example.COM", "www.example.com"},
		{"uppercase and trailing dot", "WWW.EXAMPLE.COM.", "www.example.com"},
		{"wildcard kept", "*.sub.example.com", "*.sub.example.com"},
		{"wildcard and trailing dot", "*.sub.example.com.", "*.sub.example.com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSubdomain(tt.in); got != tt.want {
				t.Fatalf("normalizeSubdomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSubdomainPassesDomainGate(t *testing.T) {
	domain := "example.com"
	// Values as reported verbatim by sources that do not normalize their
	// output: trailing-dot FQDNs from DNS-centric APIs, mixed-case hosts
	// from certificate data and code search matches.
	for _, value := range []string{
		"www.example.com",
		"www.example.com.",
		"WWW.Example.com",
		"dev.EXAMPLE.com",
		"*.sub.example.com.",
		"https://www.EXAMPLE.com",
	} {
		subdomain := replacer.Replace(normalizeSubdomain(value))
		if !strings.HasSuffix(subdomain, "."+domain) {
			t.Fatalf("expected %q to pass the domain gate, got %q", value, subdomain)
		}
	}
	for _, value := range []string{"example.com", "notexample.com", "foo.example.com.evil.org"} {
		subdomain := replacer.Replace(normalizeSubdomain(value))
		if strings.HasSuffix(subdomain, "."+domain) {
			t.Fatalf("expected %q to be rejected by the domain gate, got %q", value, subdomain)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	content := "https://8.8.8.8\n\nexample.com/path\n# comment\n  http://sub.example.com?q=1  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := loadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"8.8.8.8", "example.com", "sub.example.com"}
	if len(got) != len(want) {
		t.Fatalf("loadFromFile returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("loadFromFile returned %v, want %v", got, want)
		}
	}
}

func TestLoadFromFileMissing(t *testing.T) {
	if _, err := loadFromFile(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
