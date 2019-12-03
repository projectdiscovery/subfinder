package passive

import (
	"github.com/subfinder/subfinder/pkg/subscraping"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/archiveis"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/binaryedge"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/bufferover"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/certspotter"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/certspotterold"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/commoncrawl"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/crtsh"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/digicert"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/dnsdumpster"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/entrust"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/googleter"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/hackertarget"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/ipv4info"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/passivetotal"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/securitytrails"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/sitedossier"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/threatcrowd"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/threatminer"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/urlscan"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/virustotal"
	"github.com/subfinder/subfinder/pkg/subscraping/sources/waybackarchive"
)

// DefaultSources contains the list of sources used by default
var DefaultSources = []string{
	"archiveis",
	"binaryedge",
	"bufferover",
	"certspotter",
	"certspotterold",
	"commoncrawl",
	"crtsh",
	"digicert",
	"dnsdumpster",
	"entrust",
	"googleter",
	"hackertarget",
	"ipv4info",
	"passivetotal",
	"securitytrails",
	"sitedossier",
	"threatcrowd",
	"threatminer",
	"urlscan",
	"virustotal",
	"waybackarchive",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping.Source
}

// NewAgent creates a new agent for passive subdomain discovery
func New(sources []string, exclusions []string) *Agent { 
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping.Source)}

	agent.insertSources(sources)
	agent.removeSources(exclusions)

	return agent
}	

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "archiveis":      
			a.sources[source] = &archiveis.Source{},
		case "binaryedge":     
			a.sources[source] = &binaryedge.Source{},
		case "bufferover":     
			a.sources[source] = &bufferover.Source{},
		case "certspotter":    
			a.sources[source] = &certspotter.Source{},
		case "certspotterold": 
			a.sources[source] = &certspotterold.Source{},
		case "commoncrawl":    
			a.sources[source] = &commoncrawl.Source{},
		case "crtsh":          
			a.sources[source] = &crtsh.Source{},
		case "digicert":       
			a.sources[source] = &digicert.Source{},
		case "dnsdumpster":    
			a.sources[source] = &dnsdumpster.Source{},
		case "entrust":        
			a.sources[source] = &entrust.Source{},
		case "googleter":      
			a.sources[source] = &googleter.Source{},
		case "hackertarget":   
			a.sources[source] = &hackertarget.Source{},
		case "ipv4info":       
			a.sources[source] = &ipv4info.Source{},
		case "passivetotal":   
			a.sources[source] = &passivetotal.Source{},
		case "securitytrails": 
			a.sources[source] = &securitytrails.Source{},
		case "sitedossier":    
			a.sources[source] = &sitedossier.Source{},
		case "threatcrowd":    
			a.sources[source] = &threatcrowd.Source{},
		case "threatminer":    
			a.sources[source] = &threatminer.Source{},
		case "urlscan":        
			a.sources[source] = &urlscan.Source{},
		case "virustotal":     
			a.sources[source] = &virustotal.Source{},
		case "waybackarchive": 
			a.sources[source] = &waybackarchive.Source{},
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}