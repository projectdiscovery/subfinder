package passive

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"
)

var (
	expectedAllSources = []string{
		"alienvault",
		"anubis",
		"bevigil",
		"binaryedge",
		"bufferover",
		"c99",
		"censys",
		"certspotter",
		"chaos",
		"chinaz",
		"commoncrawl",
		"crtsh",
		"digitorus",
		"dnsdumpster",
		"dnsdb",
		"dnsrepo",
		"fofa",
		"fullhunt",
		"github",
		"hackertarget",
		"intelx",
		"passivetotal",
		"quake",
		"rapiddns",
		"riddler",
		"robtex",
		"securitytrails",
		"shodan",
		"sitedossier",
		"threatbook",
		"virustotal",
		"waybackarchive",
		"whoisxmlapi",
		"zoomeye",
		"zoomeyeapi",
		"hunter",
		// "threatminer",
		// "reconcloud",
	}

	expectedDefaultSources = []string{
		"alienvault",
		"anubis",
		"bevigil",
		"bufferover",
		"c99",
		"certspotter",
		"censys",
		"chaos",
		"chinaz",
		"crtsh",
		"digitorus",
		"dnsdumpster",
		"dnsrepo",
		"fofa",
		"fullhunt",
		"hackertarget",
		"intelx",
		"passivetotal",
		"quake",
		"robtex",
		"riddler",
		"securitytrails",
		"shodan",
		"virustotal",
		"whoisxmlapi",
		"hunter",
		// "threatminer",
		// "reconcloud",
	}

	expectedDefaultRecursiveSources = []string{
		"alienvault",
		"binaryedge",
		"bufferover",
		"certspotter",
		"crtsh",
		"dnsdumpster",
		"digitorus",
		"hackertarget",
		"passivetotal",
		"securitytrails",
		"virustotal",
		// "reconcloud",
	}
)

func TestSourceCategorization(t *testing.T) {
	defaultSources := make([]string, 0, len(AllSources))
	recursiveSources := make([]string, 0, len(AllSources))
	for _, source := range AllSources {
		sourceName := source.Name()
		if source.IsDefault() {
			defaultSources = append(defaultSources, sourceName)
		}

		if source.HasRecursiveSupport() {
			recursiveSources = append(recursiveSources, sourceName)
		}
	}

	assert.ElementsMatch(t, expectedDefaultSources, defaultSources)
	assert.ElementsMatch(t, expectedDefaultRecursiveSources, recursiveSources)
	assert.ElementsMatch(t, expectedAllSources, maps.Keys(NameSourceMap))
}

func TestSourceFiltering(t *testing.T) {
	someSources := []string{
		"alienvault",
		"chaos",
		"crtsh",
		"virustotal",
	}

	someExclusions := []string{
		"alienvault",
		"virustotal",
	}

	tests := []struct {
		sources        []string
		exclusions     []string
		withAllSources bool
		withRecursion  bool
		expectedLength int
	}{
		{someSources, someExclusions, false, false, len(someSources) - len(someExclusions)},
		{someSources, someExclusions, false, true, 1},
		{someSources, someExclusions, true, false, len(AllSources) - len(someExclusions)},
		{someSources, someExclusions, true, true, 9},

		{someSources, []string{}, false, false, len(someSources)},
		{someSources, []string{}, true, false, len(AllSources)},

		{[]string{}, []string{}, false, false, len(expectedDefaultSources)},
		{[]string{}, []string{}, false, true, 10},
		{[]string{}, []string{}, true, false, len(AllSources)},
		{[]string{}, []string{}, true, true, len(expectedDefaultRecursiveSources)},
	}
	for index, test := range tests {
		t.Run(strconv.Itoa(index+1), func(t *testing.T) {
			agent := New(test.sources, test.exclusions, test.withAllSources, test.withRecursion)

			for _, v := range agent.sources {
				fmt.Println(v.Name())
			}

			assert.Equal(t, test.expectedLength, len(agent.sources))
			agent = nil
		})
	}
}
