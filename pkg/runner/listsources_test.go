package runner

import (
	"bufio"
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSourcesInfo(t *testing.T) {
	infos := buildSourcesInfo()

	// One entry per available source.
	require.Len(t, infos, len(passive.AllSources))

	// Deterministic, name-sorted output.
	assert.True(t, sort.SliceIsSorted(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	}), "sources info must be sorted by name")

	// Every entry mirrors the source's own interface methods.
	byName := make(map[string]SourceInfo, len(infos))
	for _, info := range infos {
		byName[info.Name] = info
		assert.Contains(t, []string{"required", "optional", "none"}, info.KeyRequirement)
	}
	for _, source := range passive.AllSources {
		info, ok := byName[source.Name()]
		require.Truef(t, ok, "missing source %s", source.Name())
		assert.Equal(t, source.IsDefault(), info.Default)
		assert.Equal(t, source.HasRecursiveSupport(), info.Recursive)
		assert.Equal(t, keyRequirementString(source.KeyRequirement()), info.KeyRequirement)
	}
}

func TestWriteSourcesJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeSourcesJSON(&buf))

	// Output is JSONL: every non-empty line is a standalone, valid JSON object.
	var count int
	scanner := bufio.NewScanner(&buf)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var info SourceInfo
		require.NoErrorf(t, json.Unmarshal(line, &info), "invalid JSON line: %s", line)
		assert.NotEmpty(t, info.Name)
		count++
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, len(passive.AllSources), count)
}
