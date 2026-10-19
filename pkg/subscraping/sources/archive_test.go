package sources_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
)

// Exercise the real source parsers with an in-memory transport. No archive
// service, target hostname, or DNS resolver is contacted.
func TestArchiveSourcesPreserveHostnamePrefixes(t *testing.T) {
	hostnames := []string{
		"www.example.com",
		"2fa.example.com",
		"25mail.example.com",
		"252fmail.example.com",
		"2f.example.com",
		"25.example.com",
	}
	for _, source := range []subscraping.Source{&commoncrawl.Source{}, &waybackarchive.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			for depth := 0; depth <= 3; depth++ {
				for _, lowerEscapes := range []bool{false, true} {
					if depth == 0 && lowerEscapes {
						continue
					}
					t.Run(fmt.Sprintf("encoding_depth_%d/lowercase_escapes_%t", depth, lowerEscapes), func(t *testing.T) {
						var lines []string
						for _, hostname := range hostnames {
							line := "https://" + strings.ToUpper(hostname) + "/login"
							for range depth {
								line = url.QueryEscape(line)
							}
							if lowerEscapes {
								line = strings.NewReplacer("%3A", "%3a", "2F", "2f").Replace(line)
							}
							lines = append(lines, line)
						}
						checkArchiveResults(t, source, lines, hostnames)
					})
				}
			}
		})
	}
}

func TestArchiveSourcesKeepLastValidDecode(t *testing.T) {
	for _, source := range []subscraping.Source{&commoncrawl.Source{}, &waybackarchive.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			checkArchiveResults(t, source, []string{
				"https://2fa.example.com/100%invalid",
				url.QueryEscape("https://25mail.example.com/100%invalid"),
			}, []string{"2fa.example.com", "25mail.example.com"})
		})
	}
}

func checkArchiveResults(t *testing.T, source subscraping.Source, lines, want []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	transport := transportFunc(func(req *http.Request) (*http.Response, error) {
		var body string
		switch req.URL.Host + req.URL.Path {
		case "index.commoncrawl.org/collinfo.json":
			body = fmt.Sprintf(`[{"id":"CC-MAIN-%d-01","cdx-api":"https://index.commoncrawl.org/mock-index"}]`, time.Now().Year())
		case "index.commoncrawl.org/mock-index":
			for _, line := range lines {
				body += "com,example)/ 20260101000000 " + line + " text/html 200 ABC 123\n"
			}
		case "web.archive.org/cdx/search/cdx":
			body = strings.Join(lines, "\n") + "\n"
		default:
			return nil, fmt.Errorf("unexpected archive request: %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	got := awaitRun(t, ctx, startRun(t, ctx, source, "example.com", transport, 0))
	want = slices.Clone(want)
	slices.Sort(want)
	if got.errors != 0 || !slices.Equal(got.values, want) {
		t.Errorf("got %q with %d errors, want %q", got.values, got.errors, want)
	}
	if got.stats.Results != len(want) {
		t.Errorf("result count = %d, want %d", got.stats.Results, len(want))
	}
}

func TestArchiveSourcesDecodeMixedEscapes(t *testing.T) {
	for _, source := range []subscraping.Source{&commoncrawl.Source{}, &waybackarchive.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			checkArchiveResults(t, source, []string{
				"%2Fa.example.com/%",
				"%252fa.example.com%25",
				"https%253A%252F%252Fa.example.com%252F%25",
				"%25252fa.example.com%2525",
			}, []string{"a.example.com", "a.example.com", "a.example.com", "a.example.com"})
		})
	}
}

func TestArchiveSourcesPreserveLiteralPercentPaths(t *testing.T) {
	for _, source := range []subscraping.Source{&commoncrawl.Source{}, &waybackarchive.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			for depth := 0; depth <= 3; depth++ {
				line := "https://25mail.example.com/path%25?q=50%25"
				for range depth {
					line = url.QueryEscape(line)
				}
				checkArchiveResults(t, source, []string{line}, []string{"25mail.example.com"})
			}
		})
	}
}

func TestArchiveSourcesRejectAmbiguousPercentSpans(t *testing.T) {
	for _, source := range []subscraping.Source{&commoncrawl.Source{}, &waybackarchive.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			tooDeep := "https://a.example.com/"
			for range 4 {
				tooDeep = url.QueryEscape(tooDeep)
			}
			checkArchiveResults(t, source, []string{
				"%GGa.example.com",
				"%2xa.example.com",
				tooDeep,
				"https://a.example.com/%GG https://b.example.com/",
			}, []string{"a.example.com", "b.example.com"})
		})
	}
}

// A malformed percent must not become a new escape after adjacent valid
// escapes decode, but actual encoded delimiters must still separate hosts.
func TestArchiveSourcesRejectSynthesizedEscapes(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"%6%31.example.com", nil},
		{"%2%66a.example.com", nil},
		{"%6%2531.example.com", nil},
		{"%6%252531.example.com", nil},
		{"https://good.example.com/ %6%31.example.com", []string{"good.example.com"}},
		{"%6%31.example.com/https://b.example.com", []string{"b.example.com"}},
		{"%GG%2Fa.example.com", []string{"a.example.com"}},
		{"%GG%252Fa.example.com", []string{"a.example.com"}},
		{"%GG%25252Fa.example.com", []string{"a.example.com"}},
		{"https://good.example.com/path%25\\a.example.com", []string{"a.example.com", "good.example.com"}},
	}
	for _, source := range []subscraping.Source{&commoncrawl.Source{}, &waybackarchive.Source{}} {
		t.Run(source.Name(), func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.line, func(t *testing.T) { checkArchiveResults(t, source, []string{tc.line}, tc.want) })
			}
		})
	}
}
