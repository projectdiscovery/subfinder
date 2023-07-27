package runner

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestConfigGetDirectory(t *testing.T) {
	directory, err := GetConfigDirectory()
	if err != nil {
		t.Fatalf("Expected nil got %v while getting home\n", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Expected nil got %v while getting dir\n", err)
	}
	config := home + "/.config/subfinder"

	require.Equal(t, directory, config, "Directory and config should be equal")
}
