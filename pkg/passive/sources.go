package passive

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/certspotter"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chaos"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/crtsh"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitalyama"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/domainsproject"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/driftnet"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/hudsonrock"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/merklemap"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/onyphe"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/profundis"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/pugrecon"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/reconeer"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/redhuntlabs"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/rsecloud"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/scanmalware"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/shodanct"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/submd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/thc"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/threatcrowd"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/urlscan"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/windvane"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var AllSources = newSources()

func newSources() [52]subscraping.Source {
	return [...]subscraping.Source{
		&alienvault.Source{},
		&anubis.Source{},
		&bevigil.Source{},
		&bufferover.Source{},
		&builtwith.Source{},
		&c99.Source{},
		&censys.Source{},
		&certspotter.Source{},
		&chaos.Source{},
		&chinaz.Source{},
		&commoncrawl.Source{},
		&crtsh.Source{},
		&digitalyama.Source{},
		&digitorus.Source{},
		&dnsdb.Source{},
		&dnsdumpster.Source{},
		&dnsrepo.Source{},
		&domainsproject.Source{},
		&driftnet.Source{},
		&fofa.Source{},
		&fullhunt.Source{},
		&github.Source{},
		&hackertarget.Source{},
		&hudsonrock.Source{},
		&intelx.Source{},
		&leakix.Source{},
		&merklemap.Source{},
		&netlas.Source{},
		&onyphe.Source{},
		&profundis.Source{},
		&pugrecon.Source{},
		&quake.Source{},
		&rapiddns.Source{},
		// &reconcloud.Source{}, // failing due to cloudflare bot protection
		&reconeer.Source{},
		&redhuntlabs.Source{},
		// &riddler.Source{}, // failing due to cloudfront protection
		&robtex.Source{},
		&rsecloud.Source{},
		&scanmalware.Source{},
		&securitytrails.Source{},
		&shodan.Source{},
		&shodanct.Source{},
		&sitedossier.Source{},
		&thc.Source{},
		&threatbook.Source{},
		&threatcrowd.Source{},
		// &threatminer.Source{}, // failing  api
		&urlscan.Source{},
		&virustotal.Source{},
		&waybackarchive.Source{},
		&whoisxmlapi.Source{},
		&windvane.Source{},
		&zoomeyeapi.Source{},
		&submd.Source{},
	}
}

var sourceWarnings = mapsutil.NewSyncLockMap[string, string](
	mapsutil.WithMap(mapsutil.Map[string, string]{}))

var NameSourceMap = make(map[string]subscraping.Source, len(AllSources))

var builtinSources = make(map[string]subscraping.Source, len(AllSources))
var customSourceGates sync.Map

func init() {
	for _, currentSource := range AllSources {
		NameSourceMap[strings.ToLower(currentSource.Name())] = currentSource
		builtinSources[strings.ToLower(currentSource.Name())] = currentSource
	}
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources []subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	agent := selectSources(AllSources[:], NameSourceMap, sourceNames, excludedSourceNames, useAllSources, useSourcesSupportingRecurse)
	for _, source := range agent.sources {
		keyReq := source.KeyRequirement()
		if keyReq == subscraping.RequiredKey || keyReq == subscraping.OptionalKey {
			if apiKey := os.Getenv(fmt.Sprintf("%s_API_KEY", strings.ToUpper(source.Name()))); apiKey != "" {
				source.AddApiKeys([]string{apiKey})
			}
		}
	}
	return agent
}

// NewWithProviderConfig creates independently owned built-in sources using effective
// provider keys supplied by the caller. Registered custom sources are preserved and
// serialized across agents. It does not read environment variables. Register custom
// sources before constructing agents; registry mutation during enumeration is unsafe.
func NewWithProviderConfig(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool, keys map[string][]string) *Agent {
	available := newSources()
	byName := make(map[string]subscraping.Source, len(available))
	for _, source := range available {
		byName[strings.ToLower(source.Name())] = source
	}
	agent := selectSources(AllSources[:], NameSourceMap, sourceNames, excludedSourceNames, useAllSources, useSourcesSupportingRecurse)
	for i, source := range agent.sources {
		name := strings.ToLower(source.Name())
		providerKeys := slices.Clone(keys[name])
		if source == builtinSources[name] {
			source = byName[name]
			source.AddApiKeys(providerKeys)
		} else {
			gate, _ := customSourceGates.LoadOrStore(name, make(chan struct{}, 1))
			source = &serializedSource{Source: source, gate: gate.(chan struct{}), keys: providerKeys}
		}
		agent.sources[i] = source
	}
	return agent
}

// Custom sources have no cloning contract. Hold their gate through result draining
// and statistics capture so mutable run state cannot leak between domains.
type serializedSource struct {
	subscraping.Source
	gate  chan struct{}
	mu    sync.Mutex
	keys  []string
	stats subscraping.Statistics
}

func (s *serializedSource) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = slices.Clone(keys)
}

func (s *serializedSource) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *serializedSource) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	go func() {
		defer close(results)
		select {
		case s.gate <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-s.gate }()
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		keys := slices.Clone(s.keys)
		s.mu.Unlock()
		if len(keys) > 0 {
			s.Source.AddApiKeys(keys)
		}
		for result := range s.Source.Run(ctx, domain, session) {
			select {
			case results <- result:
			case <-ctx.Done():
				// Keep draining custom sources that use unconditional channel sends.
			}
		}
		s.mu.Lock()
		s.stats = s.Source.Statistics()
		s.mu.Unlock()
	}()
	return results
}

func selectSources(available []subscraping.Source, byName map[string]subscraping.Source, sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	sources := make(map[string]subscraping.Source, len(available))

	if useAllSources {
		maps.Copy(sources, byName)
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				if byName[source] == nil {
					gologger.Warning().Msgf("There is no source with the name: %s", source)
				} else {
					sources[source] = byName[source]
				}
			}
		} else {
			for _, currentSource := range available {
				if currentSource.IsDefault() {
					sources[currentSource.Name()] = currentSource
				}
			}
		}
	}

	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if useSourcesSupportingRecurse {
		for sourceName, source := range sources {
			if !source.HasRecursiveSupport() {
				delete(sources, sourceName)
			}
		}
	}

	if len(sources) == 0 {
		gologger.Fatal().Msg("No sources selected for this search")
	}

	gologger.Debug().Msgf("Selected source(s) for this search: %s", strings.Join(slices.Sorted(maps.Keys(sources)), ", "))

	for _, currentSource := range sources {
		if warning, ok := sourceWarnings.Get(strings.ToLower(currentSource.Name())); ok {
			gologger.Warning().Msg(warning)
		}
	}

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: slices.Collect(maps.Values(sources))}

	return agent
}
