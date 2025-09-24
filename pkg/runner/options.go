package runner

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	logutil "github.com/projectdiscovery/utils/log"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	configDir                     = folderutil.AppConfigDirOrDefault(".", "subfinder")
	defaultConfigLocation         = envutil.GetEnvOrDefault("SUBFINDER_CONFIG", filepath.Join(configDir, "config.yaml"))
	defaultProviderConfigLocation = envutil.GetEnvOrDefault("SUBFINDER_PROVIDER_CONFIG", filepath.Join(configDir, "provider-config.yaml"))
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool                // Verbose flag indicates whether to show verbose output or not
	NoColor            bool                // NoColor disables the colored output
	JSON               bool                // JSON specifies whether to use json for output format or text file
	HostIP             bool                // HostIP specifies whether to write subdomains in host:ip format
	Silent             bool                // Silent suppresses any extra text and only writes subdomains to screen
	ListSources        bool                // ListSources specifies whether to list all available sources
	RemoveWildcard     bool                // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources     bool                // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin              bool                // Stdin specifies whether stdin input was given to the process
	Version            bool                // Version specifies if we should just show version and exit
	OnlyRecursive      bool                // Recursive specifies whether to use only recursive subdomain enumeration sources
	All                bool                // All specifies whether to use all (slow) sources.
	Statistics         bool                // Statistics specifies whether to report source statistics
	Threads            int                 // Threads controls the number of threads to use for active enumerations
	Timeout            int                 // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int                 // MaxEnumerationTime is the maximum amount of time in minutes to wait for enumeration
	Domain             goflags.StringSlice // Domain is the domain to find subdomains for
	DomainsFile        string              // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string               // Output is the file to write found subdomains to.
	OutputDirectory    string               // OutputDirectory is the directory to write results to in case list of domains is given
	Sources            goflags.StringSlice  `yaml:"sources,omitempty"`         // Sources contains a comma-separated list of sources to use for enumeration
	ExcludeSources     goflags.StringSlice  `yaml:"exclude-sources,omitempty"` // ExcludeSources contains the comma-separated sources to not include in the enumeration process
	Resolvers          goflags.StringSlice  `yaml:"resolvers,omitempty"`       // Resolvers is the comma-separated resolvers to use for enumeration
	ResolverList       string               // ResolverList is a text file containing list of resolvers to use for enumeration
	Config             string               // Config contains the location of the config file
	ProviderConfig     string               // ProviderConfig contains the location of the provider config file
	Proxy              string               // HTTP proxy
	RateLimit          int                  // Global maximum number of HTTP requests to send per second
	RateLimits         goflags.RateLimitMap // Maximum number of HTTP requests to send per second
	ExcludeIps         bool
	Match              goflags.StringSlice
	Filter             goflags.StringSlice
	matchRegexes       []*regexp.Regexp
	filterRegexes      []*regexp.Regexp
	ResultCallback     OnResultCallback // OnResult callback
	DisableUpdateCheck bool             // DisableUpdateCheck disable update checking
}

// OnResultCallback (hostResult)
type OnResultCallback func(result *resolve.HostEntry)

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	logutil.DisableDefaultLogger()

	options := &Options{}

	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Subfinder is a subdomain discovery tool that discovers subdomains for websites by using passive online sources.`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Domain, "domain", "d", nil, "domains to find subdomains for", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.DomainsFile, "list", "dL", "", "file containing list of domains for subdomain discovery"),
	)

	flagSet.CreateGroup("source", "Source",
		flagSet.StringSliceVarP(&options.Sources, "sources", "s", nil, "specific sources to use for discovery (-s crtsh,github). Use -ls to display all available sources.", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVar(&options.OnlyRecursive, "recursive", false, "use only sources that can handle subdomains recursively rather than both recursive and non-recursive sources"),
		flagSet.BoolVar(&options.All, "all", false, "use all sources for enumeration (slow)"),
		flagSet.StringSliceVarP(&options.ExcludeSources, "exclude-sources", "es", nil, "sources to exclude from enumeration (-es alienvault,zoomeyeapi)", goflags.NormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.StringSliceVarP(&options.Match, "match", "m", nil, "subdomain or list of subdomain to match (file or comma separated)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Filter, "filter", "f", nil, " subdomain or list of subdomain to filter (file or comma separated)", goflags.FileNormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 0, "maximum number of http requests to send per second (global)"),
		flagSet.RateLimitMapVarP(&options.RateLimits, "rate-limits", "rls", defaultRateLimits, "maximum number of http requests to send per second for providers in key=value format (-rls hackertarget=10/m)", goflags.NormalizedStringSliceOptions),
		flagSet.IntVar(&options.Threads, "t", 10, "number of concurrent goroutines for resolving (-active only)"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update subfinder to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic subfinder update check"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.JSON, "json", "oJ", false, "write output in JSONL(ines) format"),
		flagSet.StringVarP(&options.OutputDirectory, "output-dir", "oD", "", "directory to write output (-dL only)"),
		flagSet.BoolVarP(&options.CaptureSources, "collect-sources", "cs", false, "include all sources in the output (-json only)"),
		flagSet.BoolVarP(&options.HostIP, "ip", "oI", false, "include host IP in output (-active only)"),
	)

	flagSet.CreateGroup("configuration", "Configuration",
		flagSet.StringVar(&options.Config, "config", defaultConfigLocation, "flag config file"),
		flagSet.StringVarP(&options.ProviderConfig, "provider-config", "pc", defaultProviderConfigLocation, "provider config file"),
		flagSet.StringSliceVar(&options.Resolvers, "r", nil, "comma separated list of resolvers to use", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ResolverList, "rlist", "rL", "", "file containing list of resolvers to use"),
		flagSet.BoolVarP(&options.RemoveWildcard, "active", "nW", false, "display active subdomains only"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "http proxy to use with subfinder"),
		flagSet.BoolVarP(&options.ExcludeIps, "exclude-ip", "ei", false, "exclude IPs from the list of domains"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "show only subdomains in output"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of subfinder"),
		flagSet.BoolVar(&options.Verbose, "v", false, "show verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable color in output"),
		flagSet.BoolVarP(&options.ListSources, "list-sources", "ls", false, "list all available sources"),
		flagSet.BoolVar(&options.Statistics, "stats", false, "report source statistics"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Timeout, "timeout", 30, "seconds to wait before timing out"),
		flagSet.IntVar(&options.MaxEnumerationTime, "max-time", 10, "minutes to wait for enumeration results"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// set chaos mode
	chaos.IsSDK = false

	if exists := fileutil.FileExists(defaultProviderConfigLocation); !exists {
		if err := createProviderConfigYAML(defaultProviderConfigLocation); err != nil {
			gologger.Error().Msgf("Could not create provider config file: %s\n", err)
		}
	}

	if options.Config != defaultConfigLocation {
		// An empty source file is not a fatal error
		if err := flagSet.MergeConfigFile(options.Config); err != nil && !errors.Is(err, io.EOF) {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	// Default output is stdout
	options.Output = os.Stdout

	// Check if stdin pipe was given
	options.Stdin = fileutil.HasStdin()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		gologger.Info().Msgf("Subfinder Config Directory: %s", configDir)
		os.Exit(0)
	}

	options.preProcessDomains()

	options.ConfigureOutput()
	showBanner()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("subfinder", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("subfinder version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current subfinder version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

// loadProvidersFrom runs the app with source config
func (options *Options) loadProvidersFrom(location string) {
	// todo: move elsewhere
	if len(options.Resolvers) == 0 {
		options.Resolvers = resolve.DefaultResolvers
	}

	// We skip bailing out if file doesn't exist because we'll create it
	// at the end of options parsing from default via goflags.
	if err := UnmarshalFrom(location); err != nil && (!strings.Contains(err.Error(), "file doesn't exist") || errors.Is(err, os.ErrNotExist)) {
		gologger.Error().Msgf("Could not read providers from %s: %s\n", location, err)
	}
}

func listSources(options *Options) {
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(passive.AllSources))
	gologger.Info().Msgf("Sources marked with an * need key(s) or token(s) to work.\n")
	gologger.Info().Msgf("You can modify %s to configure your keys/tokens.\n\n", options.ProviderConfig)

	for _, source := range passive.AllSources {
		message := "%s\n"
		sourceName := source.Name()
		if source.NeedsKey() {
			message = "%s *\n"
		}
		gologger.Silent().Msgf(message, sourceName)
	}
}

func (options *Options) preProcessDomains() {
	for i, domain := range options.Domain {
		options.Domain[i] = preprocessDomain(domain)
	}
}

var defaultRateLimits = []string{
	"github=30/m",
	"fullhunt=60/m",
	"pugrecon=10/s",
	fmt.Sprintf("robtex=%d/ms", uint(math.MaxUint)),
	"securitytrails=1/s",
	"shodan=1/s",
	"virustotal=4/m",
	"hackertarget=2/s",
	// "threatminer=10/m",
	"waybackarchive=15/m",
	"whoisxmlapi=50/s",
	"securitytrails=2/s",
	"sitedossier=8/m",
	"netlas=1/s",
	// "gitlab=2/s",
	"github=83/m",
	"hudsonrock=5/s",
}
