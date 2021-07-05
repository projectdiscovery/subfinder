package passive

import (
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/archiveis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/binaryedge"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/passivetotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/recon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/riddler"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sonarsearch"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/spyse"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sublist3r"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatminer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeye"
)

// DefaultSources contains the list of fast sources used by default.
var DefaultSources = []string{
	"alienvault",
	"anubis",
	"bufferover",
	"certspotter",
	"censys",
	"chaos",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"intelx",
	"passivetotal",
	"robtex",
	"riddler",
	"securitytrails",
	"shodan",
	"spyse",
	"sublist3r",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"fofa",
}

// DefaultRecursiveSources contains list of default recursive sources
var DefaultRecursiveSources = []string{
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
	"sublist3r",
	"virustotal",
}

// DefaultAllSources contains list of all sources
var DefaultAllSources = []string{
	"alienvault",
	"anubis",
	"archiveis",
	"binaryedge",
	"bufferover",
	"censys",
	"certspotter",
	"chaos",
	"commoncrawl",
	"crtsh",
	"dnsdumpster",
	"dnsdb",
	"github",
	"hackertarget",
	"intelx",
	"passivetotal",
	"rapiddns",
	"riddler",
	"recon",
	"robtex",
	"securitytrails",
	"shodan",
	"sitedossier",
	"sonarsearch",
	"spyse",
	"sublist3r",
	"threatbook",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"waybackarchive",
	"zoomeye",
	"fofa",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sources, exclusions []string) *Agent {
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping.Source)}

	agent.addSources(sources)
	agent.removeSources(exclusions)

	return agent
}

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "alienvault":
			a.sources[source] = &alienvault.Source{}
		case "anubis":
			a.sources[source] = &anubis.Source{}
		case "archiveis":
			a.sources[source] = &archiveis.Source{}
		case "binaryedge":
			a.sources[source] = &binaryedge.Source{}
		case "bufferover":
			a.sources[source] = &bufferover.Source{}
		case "censys":
			a.sources[source] = &censys.Source{}
		case "certspotter":
			a.sources[source] = &certspotter.Source{}
		case "chaos":
			a.sources[source] = &chaos.Source{}
		case "commoncrawl":
			a.sources[source] = &commoncrawl.Source{}
		case "crtsh":
			a.sources[source] = &crtsh.Source{}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster.Source{}
		case "dnsdb":
			a.sources[source] = &dnsdb.Source{}
		case "github":
			a.sources[source] = &github.Source{}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{}
		case "intelx":
			a.sources[source] = &intelx.Source{}
		case "passivetotal":
			a.sources[source] = &passivetotal.Source{}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{}
		case "recon":
			a.sources[source] = &recon.Source{}
		case "riddler":
			a.sources[source] = &riddler.Source{}
		case "robtex":
			a.sources[source] = &robtex.Source{}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{}
		case "shodan":
			a.sources[source] = &shodan.Source{}
		case "sitedossier":
			a.sources[source] = &sitedossier.Source{}
		case "sonarsearch":
			a.sources[source] = &sonarsearch.Source{}
		case "spyse":
			a.sources[source] = &spyse.Source{}
		case "sublist3r":
			a.sources[source] = &sublist3r.Source{}
		case "threatbook":
			a.sources[source] = &threatbook.Source{}
		case "threatcrowd":
			a.sources[source] = &threatcrowd.Source{}
		case "threatminer":
			a.sources[source] = &threatminer.Source{}
		case "virustotal":
			a.sources[source] = &virustotal.Source{}
		case "waybackarchive":
			a.sources[source] = &waybackarchive.Source{}
		case "zoomeye":
			a.sources[source] = &zoomeye.Source{}
		case "fofa":
			a.sources[source] = &fofa.Source{}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
