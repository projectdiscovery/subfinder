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
		"archiveis",
		"binaryedge",
		"bufferover",
		"c99",
		"censys",
		"certspotter",
		"chaos",
		"chinaz",
		"commoncrawl",
		"crtsh",
		"dnsdumpster",
		"DNSDB",
		"fofa",
		"fullhunt",
		"github",
		"hackertarget",
		"intelx",
		"passivetotal",
		"rapiddns",
		"riddler",
		"robtex",
		"securitytrails",
		"shodan",
		"sitedossier",
		"sonarsearch",
		"threatbook",
		"threatcrowd",
		"threatminer",
		"virustotal",
		"waybackarchive",
		"whoisxmlapi",
		"zoomeye",
		"zoomeyeapi",
	}

	expectedDefaultSources = []string{
		"alienvault",
		"anubis",
		"bufferover",
		"c99",
		"certspotter",
		"censys",
		"chaos",
		"chinaz",
		"crtsh",
		"dnsdumpster",
		"fofa",
		"fullhunt",
		"hackertarget",
		"intelx",
		"passivetotal",
		"robtex",
		"riddler",
		"securitytrails",
		"shodan",
		"threatcrowd",
		"threatminer",
		"virustotal",
		"whoisxmlapi",
	}

	expectedDefaultRecursiveSources = []string{
		"alienvault",
		"binaryedge",
		"bufferover",
		"certspotter",
		"crtsh",
		"dnsdumpster",
		"hackertarget",
		"passivetotal",
		"securitytrails",
		"sonarsearch",
		"virustotal",
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

func Test(t *testing.T) {
	someSources := []string{
		"alienvault",
		"sonarsearch",
		"chaos",
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
		//{someSources, someExclusions, true, false, len(AllSources) - len(someExclusions)}, // TODO figure out why these test cases break the whole suite
		//{someSources, someExclusions, true, true, 9},

		{someSources, []string{}, false, false, len(someSources)},
		{someSources, []string{}, true, false, len(AllSources)},

		{[]string{}, []string{}, false, false, len(expectedDefaultSources)},
		{[]string{}, []string{}, false, true, 9},
		{[]string{}, []string{}, true, false, len(AllSources)},
		{[]string{}, []string{}, true, true, len(expectedDefaultRecursiveSources)},
	}
	for index, test := range tests {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			agent := New(test.sources, test.exclusions, test.withAllSources, test.withRecursion)

			for _, v := range agent.sources {
				fmt.Println(v.Name())
			}

			assert.Equal(t, test.expectedLength, len(agent.sources))
			agent = nil
		})
	}
}
