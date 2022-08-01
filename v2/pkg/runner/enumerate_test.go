package runner

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestFilterAndMatchSubdomainForMatch(t *testing.T) {
	options := &Options{}
	options.Domain = []string{"example.com"}
	options.Threads = 10
	options.Timeout = 10
	options.Output = os.Stdout
	options.Match = []string{"*.example.com"}
	err := options.validateOptions()
	if err != nil {
		t.Fatalf("Expected nil got %v while validation\n", err)
	}
	runner, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Expected nil got %v while creating runner\n", err)
	}
	match := runner.filterAndMatchSubdomain("ns.example.com")
	require.True(t, match, "Expecting a boolean value ")
}

func TestFilterAndMatchSubdomainForFilter(t *testing.T) {
	options := &Options{}
	options.Domain = []string{"example.com"}
	options.Threads = 10
	options.Timeout = 10
	options.Output = os.Stdout
	options.Filter = []string{"*.example.com"}
	err := options.validateOptions()
	if err != nil {
		t.Fatalf("Expected nil got %v while validation\n", err)
	}
	runner, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Expected nil got %v while creating runner\n", err)
	}
	match := runner.filterAndMatchSubdomain("ns.example.com")
	require.False(t, match, "Expecting a False value ")
}
