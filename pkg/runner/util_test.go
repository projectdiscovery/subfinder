package runner

import (
	"os"
	"path/filepath"
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
