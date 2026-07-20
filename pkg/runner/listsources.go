package runner

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// SourceInfo is the machine-readable description of a passive source emitted by
// `-ls -oJ`. It exposes the source properties that are otherwise only implied by
// the `*`/`~` markers of the human-readable listing, so tooling can select
// sources programmatically (e.g. only key-less or only recursive sources).
type SourceInfo struct {
	Name           string `json:"name"`
	Default        bool   `json:"default"`
	Recursive      bool   `json:"recursive"`
	KeyRequirement string `json:"keyRequirement"`
}

// keyRequirementString maps a KeyRequirement to a stable string label.
func keyRequirementString(k subscraping.KeyRequirement) string {
	switch k {
	case subscraping.RequiredKey:
		return "required"
	case subscraping.OptionalKey:
		return "optional"
	default:
		return "none"
	}
}

// buildSourcesInfo returns metadata for every available source, sorted by name
// so the output is deterministic.
func buildSourcesInfo() []SourceInfo {
	infos := make([]SourceInfo, 0, len(passive.AllSources))
	for _, source := range passive.AllSources {
		infos = append(infos, SourceInfo{
			Name:           source.Name(),
			Default:        source.IsDefault(),
			Recursive:      source.HasRecursiveSupport(),
			KeyRequirement: keyRequirementString(source.KeyRequirement()),
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}

// writeSourcesJSON writes the source metadata as JSONL (one object per line),
// matching the JSONL convention used elsewhere for -oJ output.
func writeSourcesJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	for _, info := range buildSourcesInfo() {
		if err := encoder.Encode(info); err != nil {
			return err
		}
	}
	return nil
}
