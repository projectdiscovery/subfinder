package runner

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

func printStatistics(stats map[string]subscraping.Statistics) {

	sources := slices.Sorted(maps.Keys(stats))

	var lines []string
	var skipped []string

	for _, source := range sources {
		sourceStats := stats[source]
		if sourceStats.Skipped {
			skipped = append(skipped, fmt.Sprintf(" %s", source))
		} else {
			lines = append(lines, fmt.Sprintf(" %-20s %-10s %10d %10d %10d", source, sourceStats.TimeTaken.Round(time.Millisecond).String(), sourceStats.Results, sourceStats.Requests, sourceStats.Errors))
		}
	}

	if len(lines) > 0 {
		gologger.Print().Msgf("\n Source               Duration      Results   Requests     Errors\n%s\n", strings.Repeat("─", 68))
		gologger.Print().Msg(strings.Join(lines, "\n"))
		gologger.Print().Msgf("\n")
	}

	if len(skipped) > 0 {
		gologger.Print().Msgf("\n The following sources were included but skipped...\n\n")
		gologger.Print().Msg(strings.Join(skipped, "\n"))
		gologger.Print().Msgf("\n\n")
	}
}

func (r *Runner) GetStatistics() map[string]subscraping.Statistics {
	return r.passiveAgent.GetStatistics()
}
