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
		"domainsproject",
		"driftnet",
		"fofa",
		"fullhunt",
		"github",
		"hackertarget",
		"intelx",
		"netlas",
		"onyphe",
		"quake",
		"pugrecon",
		"rapiddns",
		"redhuntlabs",
		// "riddler", // failing due to cloudfront protection
		"robtex",
		"rsecloud",
		"securitytrails",
		"profundis",
		"shodan",
		"sitedossier",
		"threatbook",
		"threatcrowd",
		"virustotal",
		"waybackarchive",
		"whoisxmlapi",
		"windvane",
		"zoomeyeapi",
		"leakix",
		"facebook",
		// "threatminer",
		// "reconcloud",
		"builtwith",
		"hudsonrock",
		"digitalyama",
		"merklemap",
		"thc",
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
		"domainsproject",
		"dnsrepo",
		"driftnet",
		"fofa",
		"fullhunt",
		"hackertarget",
		"intelx",
		"onyphe",
		"quake",
		"redhuntlabs",
		"robtex",
		// "riddler", // failing due to cloudfront protection
		"rsecloud",
		"securitytrails",
		"profundis",
		"shodan",
		"windvane",
		"virustotal",
		"whoisxmlapi",
		"leakix",
		"facebook",
		// "threatminer",
		// "reconcloud",
		"builtwith",
		"digitalyama",
		"thc",
	}

	expectedDefaultRecursiveSources = []string{
		"alienvault",
		"bufferover",
		"certspotter",
		"crtsh",
		"dnsdb",
		"digitorus",
		"driftnet",
		"hackertarget",
		"securitytrails",
		"virustotal",
		"leakix",
		"facebook",
		"merklemap",
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

// Review: not sure if this test is necessary/useful
// implementation is straightforward where sources are stored in maps and filtered based on options
// the test is just checking if the filtering works as expected using count of sources
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

		{someSources, []string{}, false, false, len(someSources)},
		{someSources, []string{}, true, false, len(AllSources)},

		{[]string{}, []string{}, false, false, len(expectedDefaultSources)},
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
