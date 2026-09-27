package runner

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/stretchr/testify/require"
)

func TestRegexResultFilters(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options Options
		host    string
		want    bool
	}{
		{"no filters", Options{}, "www.example.com", true},
		{"numbered hosts", Options{MatchRegex: []string{`^api[0-9]{1,3}\.example\.com$`}}, "api12.example.com", true},
		{"numbered hosts reject letters", Options{MatchRegex: []string{`^api[0-9]{1,3}\.example\.com$`}}, "apiab.example.com", false},
		{"alternation", Options{MatchRegex: []string{`^(api|web)\.`}}, "web.example.com", true},
		{"case insensitive", Options{MatchRegex: []string{`(?i)^API\.`}}, "api.example.com", true},
		{"unanchored", Options{MatchRegex: []string{`api`}}, "myapi.example.com", true},
		{"multiple regexes", Options{MatchRegex: []string{`^api\.`, `^web\.`}}, "web.example.com", true},
		{"wildcard include union", Options{Match: []string{"*.example.com"}, MatchRegex: []string{`^api\.`}}, "web.example.com", true},
		{"regex include union", Options{Match: []string{"*.other.com"}, MatchRegex: []string{`^api\.`}}, "api.example.com", true},
		{"no include matched", Options{Match: []string{"*.other.com"}, MatchRegex: []string{`^api\.`}}, "web.example.com", false},
		{"regex exclusion wins", Options{Match: []string{"*.example.com"}, FilterRegex: []string{`^dev\.`}}, "dev.example.com", false},
		{"wildcard exclusion wins", Options{MatchRegex: []string{`^dev\.`}, Filter: []string{"*.example.com"}}, "dev.example.com", false},
		{"multiple exclusions", Options{FilterRegex: []string{`^dev\.`, `^test\.`}}, "test.example.com", false},
		{"wildcard still anchored", Options{Match: []string{"api.example.com"}}, "myapi.example.com", false},
		{"wildcard still literal dots", Options{Match: []string{"api.example.com"}}, "apiXexample.com", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.options.compileFilters())
			r := &Runner{options: &tt.options}
			require.Equal(t, tt.want, r.filterAndMatchSubdomain(tt.host))
		})
	}
}

func TestNewRunnerRejectsInvalidRegexFilters(t *testing.T) {
	for _, tt := range []struct {
		options Options
		flag    string
	}{
		{Options{MatchRegex: []string{"["}}, "match-regex"},
		{Options{FilterRegex: []string{"["}}, "filter-regex"},
	} {
		t.Run(tt.flag, func(t *testing.T) {
			r, err := NewRunner(&tt.options)
			require.Nil(t, r)
			require.ErrorContains(t, err, tt.flag)
			require.ErrorContains(t, err, `"["`)
		})
	}
}

func TestRegexFiltersEnumeration(t *testing.T) {
	for _, tt := range []struct {
		name   string
		json   bool
		legacy bool
	}{
		{name: "text"},
		{name: "json", json: true},
		{name: "SDK wildcard filters", legacy: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := &delayedSource{}
			_ = delayedRunner(t, 1, source) // Register a local source, with cleanup.
			providerConfig := filepath.Join(t.TempDir(), "providers.yaml")
			require.NoError(t, os.WriteFile(providerConfig, []byte("{}"), 0600))
			var callbacks []string
			options := &Options{
				Sources:            []string{source.Name()},
				ProviderConfig:     providerConfig,
				Threads:            2,
				Timeout:            1,
				MaxEnumerationTime: 1,
				JSON:               tt.json,
				CaptureSources:     tt.json,
				MatchRegex:         []string{`^www\.target-[0-9]{1,2}\.example$`},
				FilterRegex:        []string{`target-1\.`},
				ResultCallback:     func(entry *resolve.HostEntry) { callbacks = append(callbacks, entry.Host) },
			}
			if tt.legacy {
				options.MatchRegex, options.FilterRegex = nil, nil
				options.Match = []string{"www.target-*.example"}
				options.Filter = []string{"www.target-1.example", "www.target-abc.example"}
			}
			r, err := NewRunner(options)
			require.NoError(t, err)
			var output strings.Builder
			err = r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader("target-1.example\ntarget-22.example\ntarget-abc.example\n"), []io.Writer{&output})
			require.NoError(t, err)
			require.Equal(t, []string{"www.target-22.example"}, callbacks)
			if tt.json {
				var result struct {
					Host string `json:"host"`
				}
				require.NoError(t, json.Unmarshal([]byte(output.String()), &result))
				require.Equal(t, "www.target-22.example", result.Host)
			} else {
				require.Equal(t, "www.target-22.example\n", output.String())
			}
		})
	}
}

func TestRegexFilterFlags(t *testing.T) {
	if os.Getenv("SUBFINDER_TEST_REGEX_FLAGS") == "1" {
		os.Args = []string{"subfinder", "-d", "example.com", "-silent", "-duc",
			"-match-regex", `^api[0-9]{1,3}\.`, "-match-regex", `^web\.`,
			"-filter-regex", `(^|\.)dev\.`}
		options := ParseOptions()
		_ = json.NewEncoder(os.Stdout).Encode([]goflags.StringSlice{options.MatchRegex, options.FilterRegex})
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegexFilterFlags$")
	configDir := t.TempDir()
	cmd.Env = append(os.Environ(), "SUBFINDER_TEST_REGEX_FLAGS=1",
		"SUBFINDER_CONFIG="+filepath.Join(configDir, "config.yaml"),
		"SUBFINDER_PROVIDER_CONFIG="+filepath.Join(configDir, "providers.yaml"))
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
	var patterns [][]string
	require.NoError(t, json.Unmarshal(output, &patterns), "%s", output)
	require.Equal(t, [][]string{{`^api[0-9]{1,3}\.`, `^web\.`}, {`(^|\.)dev\.`}}, patterns)
}
