package runner

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterAndMatchSubdomain(t *testing.T) {
	options := &Options{}
	options.Domain = []string{"example.com"}
	options.Threads = 10
	options.Timeout = 10
	options.Output = os.Stdout
	t.Run("Literal Match", func(t *testing.T) {
		options.Match = []string{"req.example.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		match := runner.filterAndMatchSubdomain("req.example.com")
		require.True(t, match, "Expecting a boolean True value ")
	})
	t.Run("Multiple Wildcards Match", func(t *testing.T) {
		options.Match = []string{"*.ns.*.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		subdomain := []string{"a.ns.example.com", "b.ns.hackerone.com"}
		for _, sub := range subdomain {
			match := runner.filterAndMatchSubdomain(sub)
			require.True(t, match, "Expecting a boolean True value ")
		}
	})
	t.Run("Sequential Match", func(t *testing.T) {
		options.Match = []string{"*.ns.example.com", "*.hackerone.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		subdomain := []string{"a.ns.example.com", "b.hackerone.com"}
		for _, sub := range subdomain {
			match := runner.filterAndMatchSubdomain(sub)
			require.True(t, match, "Expecting a boolean True value ")
		}
	})
	t.Run("Literal Filter", func(t *testing.T) {
		options.Filter = []string{"req.example.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		match := runner.filterAndMatchSubdomain("req.example.com")
		require.False(t, match, "Expecting a boolean False value ")
	})
	t.Run("Multiple Wildcards Filter", func(t *testing.T) {
		options.Filter = []string{"*.ns.*.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		subdomain := []string{"a.ns.example.com", "b.ns.hackerone.com"}
		for _, sub := range subdomain {
			match := runner.filterAndMatchSubdomain(sub)
			require.False(t, match, "Expecting a boolean False value ")
		}
	})
	t.Run("Sequential Filter", func(t *testing.T) {
		options.Filter = []string{"*.ns.example.com", "*.hackerone.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		subdomain := []string{"a.ns.example.com", "b.hackerone.com"}
		for _, sub := range subdomain {
			match := runner.filterAndMatchSubdomain(sub)
			require.False(t, match, "Expecting a boolean False value ")
		}
	})
	t.Run("Filter and Match", func(t *testing.T) {
		options.Filter = []string{"example.com"}
		options.Match = []string{"hackerone.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		subdomain := []string{"example.com", "example.com"}
		for _, sub := range subdomain {
			match := runner.filterAndMatchSubdomain(sub)
			require.False(t, match, "Expecting a boolean False value ")
		}
	})

	t.Run("Filter and Match - Same Root Domain", func(t *testing.T) {
		options.Filter = []string{"example.com"}
		options.Match = []string{"www.example.com"}
		err := options.validateOptions()
		if err != nil {
			t.Fatalf("Expected nil got %v while validation\n", err)
		}
		runner, err := NewRunner(options)
		if err != nil {
			t.Fatalf("Expected nil got %v while creating runner\n", err)
		}
		subdomain := map[string]string{"filter": "example.com", "match": "www.example.com"}
		for key, sub := range subdomain {
			result := runner.filterAndMatchSubdomain(sub)
			if key == "filter" {
				require.False(t, result, "Expecting a boolean False value ")
			} else {
				require.True(t, result, "Expecting a boolean True value ")
			}
		}
	})
}
