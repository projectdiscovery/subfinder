//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
// All Rights Reserved

// Passive Subdomain Discovery Helper method
// Calls all the functions and also manages error handling
package passive

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/bogdanovich/dns_resolver"

	"github.com/Ice3man543/subfinder/libsubfinder/engines/resolver"
	"github.com/Ice3man543/subfinder/libsubfinder/helper"
	"github.com/Ice3man543/subfinder/libsubfinder/output"

	// Load different Passive data sources
	"github.com/Ice3man543/subfinder/libsubfinder/sources/ask"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/baidu"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/bing"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/censys"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/certdb"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/certspotter"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/crtsh"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/dnsdb"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/dnsdumpster"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/findsubdomains"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/hackertarget"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/netcraft"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/passivetotal"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/ptrarchive"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/riddler"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/securitytrails"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/threatcrowd"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/threatminer"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/virustotal"
	"github.com/Ice3man543/subfinder/libsubfinder/sources/waybackarchive"
)

//DomainList contain the list of domains
var DomainList []string

// Source configuration structure specifying what should we use
// to do passive subdomain discovery.
type Source struct {
	Ask            bool
	Baidu          bool
	Bing           bool
	Censys         bool
	Certdb         bool
	Crtsh          bool
	Certspotter    bool
	Dnsdb          bool
	Dnsdumpster    bool
	Findsubdomains bool
	Hackertarget   bool
	Netcraft       bool
	Passivetotal   bool
	Ptrarchive     bool
	Riddler        bool
	Securitytrails bool
	Threatcrowd    bool
	Threatminer    bool
	Virustotal     bool
	Waybackarchive bool
}

func (s *Source) enableAll() {
	s.Ask = true
	s.Baidu = true
	s.Bing = true
	s.Censys = true
	s.Certdb = true
	s.Certspotter = true
	s.Crtsh = true
	s.Dnsdb = true
	s.Dnsdumpster = true
	s.Findsubdomains = true
	s.Hackertarget = true
	s.Netcraft = true
	s.Passivetotal = true
	s.Ptrarchive = true
	s.Riddler = true
	s.Securitytrails = true
	s.Threatcrowd = true
	s.Threatminer = true
	s.Virustotal = true
	s.Waybackarchive = true
}

func (s *Source) enable(dataSources []string) {
	for _, source := range dataSources {
		switch source {
		case "ask":
			s.Ask = true
		case "baidu":
			s.Baidu = true
		case "bing":
			s.Bing = true
		case "censys":
			s.Censys = true
		case "certdb":
			s.Certdb = true
		case "certspotter":
			s.Certspotter = true
		case "crtsh":
			s.Crtsh = true
		case "dnsdb":
			s.Dnsdb = true
		case "dnsdumpster":
			s.Dnsdumpster = true
		case "findsubdomains":
			s.Findsubdomains = true
		case "hackertarget":
			s.Hackertarget = true
		case "netcraft":
			s.Netcraft = true
		case "passivetotal":
			s.Passivetotal = true
		case "ptrarchive":
			s.Ptrarchive = true
		case "riddler":
			s.Riddler = true
		case "securitytrails":
			s.Securitytrails = true
		case "threatcrowd":
			s.Threatcrowd = true
		case "threatminer":
			s.Threatminer = true
		case "virustotal":
			s.Virustotal = true
		case "waybackarchive":
			s.Waybackarchive = true
		}
	}
}

func (s *Source) printSummary() {
	if s.Ask {
		fmt.Printf("\nRunning Source: %sAsk%s", helper.Info, helper.Reset)
	}
	if s.Baidu {
		fmt.Printf("\nRunning Source: %sBaidu%s", helper.Info, helper.Reset)
	}
	if s.Bing {
		fmt.Printf("\nRunning Source: %sBing%s", helper.Info, helper.Reset)
	}
	if s.Censys {
		fmt.Printf("\nRunning Source: %sCensys%s", helper.Info, helper.Reset)
	}
	if s.Certdb {
		fmt.Printf("\nRunning Source: %sCertDB%s", helper.Info, helper.Reset)
	}
	if s.Certspotter {
		fmt.Printf("\nRunning Source: %sCertspotter%s", helper.Info, helper.Reset)
	}
	if s.Crtsh {
		fmt.Printf("\nRunning Source: %sCrt.sh%s", helper.Info, helper.Reset)
	}
	if s.Dnsdb {
		fmt.Printf("\nRunning Source: %sDnsdb%s", helper.Info, helper.Reset)
	}
	if s.Dnsdumpster {
		fmt.Printf("\nRunning Source: %sDNSDumpster%s", helper.Info, helper.Reset)
	}
	if s.Findsubdomains {
		fmt.Printf("\nRunning Source: %sFindsubdomains%s", helper.Info, helper.Reset)
	}
	if s.Hackertarget {
		fmt.Printf("\nRunning Source: %sHackertarget%s", helper.Info, helper.Reset)
	}
	if s.Netcraft {
		fmt.Printf("\nRunning Source: %sNetcraft%s\n", helper.Info, helper.Reset)
	}
	if s.Passivetotal {
		fmt.Printf("\nRunning Source: %sPassiveTotal%s", helper.Info, helper.Reset)
	}
	if s.Ptrarchive {
		fmt.Printf("\nRunning Source: %sPTRArchive%s", helper.Info, helper.Reset)
	}
	if s.Riddler {
		fmt.Printf("\nRunning Source: %sRiddler%s", helper.Info, helper.Reset)
	}
	if s.Securitytrails {
		fmt.Printf("\nRunning Source: %sSecuritytrails%s", helper.Info, helper.Reset)
	}
	if s.Threatcrowd {
		fmt.Printf("\nRunning Source: %sThreatcrowd%s", helper.Info, helper.Reset)
	}
	if s.Threatminer {
		fmt.Printf("\nRunning Source: %sThreatMiner%s", helper.Info, helper.Reset)
	}
	if s.Virustotal {
		fmt.Printf("\nRunning Source: %sVirustotal%s", helper.Info, helper.Reset)
	}
	if s.Waybackarchive {
		fmt.Printf("\nRunning Source: %sWaybackArchive%s", helper.Info, helper.Reset)
	}
}

//nbrActive ses reflection to get automatic active amount of searches
func (s Source) nbrActive() int {
	activeSearches := 0
	values := reflect.ValueOf(s)
	configNumbers := (reflect.TypeOf(s)).NumField()
	for i := 0; i < configNumbers; i++ {
		config := values.Field(i)
		if config.Kind() == reflect.Bool && config.Bool() {
			activeSearches++
		}
	}
	return activeSearches
}

func discover(state *helper.State, domain string, sourceConfig *Source) (subdomains []string) {

	var finalPassiveSubdomains []string

	if strings.Contains(domain, "*.") {
		domain = strings.Split(domain, "*.")[1]
	}

	// Now, perform checks for wildcard ip
	helper.Resolver = dns_resolver.New(state.LoadResolver)

	// Initialize Wildcard Subdomains
	state.IsWildcard, state.WildcardIP = helper.InitWildcard(domain)
	if state.IsWildcard == true {
		if state.Silent != true {
			fmt.Printf("\nFound Wildcard DNS at %s", domain)
			for _, ip := range state.WildcardIP {
				fmt.Printf("\n - %s", ip)
			}
		}
	}

	domainDiscoverPool := helper.NewPool(sourceConfig.nbrActive())
	domainDiscoverPool.Run()

	domainDiscoverPool.Wait()

	if state.Silent != true {
		fmt.Printf("\nRunning enumeration on %s", domain)
	}

	// Create goroutines for added speed and recieve data via channels
	// Check if we the user has specified custom sources and if yes, run them
	// via if statements.
	if sourceConfig.Crtsh {
		domainDiscoverPool.Add(crtsh.Query, domain, state)
	}
	if sourceConfig.Certdb {
		domainDiscoverPool.Add(certdb.Query, domain, state)
	}
	if sourceConfig.Certspotter {
		domainDiscoverPool.Add(certspotter.Query, domain, state)
	}
	if sourceConfig.Threatcrowd {
		domainDiscoverPool.Add(threatcrowd.Query, domain, state)
	}
	if sourceConfig.Findsubdomains {
		domainDiscoverPool.Add(findsubdomains.Query, domain, state)
	}
	if sourceConfig.Dnsdumpster {
		domainDiscoverPool.Add(dnsdumpster.Query, domain, state)
	}
	if sourceConfig.Passivetotal {
		domainDiscoverPool.Add(passivetotal.Query, domain, state)
	}
	if sourceConfig.Ptrarchive {
		domainDiscoverPool.Add(ptrarchive.Query, domain, state)
	}
	if sourceConfig.Hackertarget {
		domainDiscoverPool.Add(hackertarget.Query, domain, state)
	}
	if sourceConfig.Virustotal {
		domainDiscoverPool.Add(virustotal.Query, domain, state)
	}
	if sourceConfig.Securitytrails {
		domainDiscoverPool.Add(securitytrails.Query, domain, state)
	}
	if sourceConfig.Netcraft {
		domainDiscoverPool.Add(netcraft.Query, domain, state)
	}
	if sourceConfig.Waybackarchive {
		domainDiscoverPool.Add(waybackarchive.Query, domain, state)
	}
	if sourceConfig.Threatminer {
		domainDiscoverPool.Add(threatminer.Query, domain, state)
	}
	if sourceConfig.Riddler {
		domainDiscoverPool.Add(riddler.Query, domain, state)
	}
	if sourceConfig.Censys {
		domainDiscoverPool.Add(censys.Query, domain, state)
	}
	if sourceConfig.Dnsdb {
		domainDiscoverPool.Add(dnsdb.Query, domain, state)
	}
	if sourceConfig.Baidu {
		domainDiscoverPool.Add(baidu.Query, domain, state)
	}
	if sourceConfig.Bing {
		domainDiscoverPool.Add(bing.Query, domain, state)
	}
	if sourceConfig.Ask {
		domainDiscoverPool.Add(ask.Query, domain, state)
	}

	domainDiscoverPool.Wait()

	completedJobs := domainDiscoverPool.Results()
	for _, job := range completedJobs {
		if job.Err != nil {
			// some error occured
			if !state.Silent {
				fmt.Printf("\nerror: %v\n", job.Err)
			}
		}
		results := job.Result.([]string)
		for _, subdomain := range results {
			finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
		}
	}

	domainDiscoverPool.Stop()

	// Now remove duplicate items from the slice
	uniquePassiveSubdomains := helper.Unique(finalPassiveSubdomains)
	// Now, validate all subdomains found
	validPassiveSubdomains := helper.Validate(domain, uniquePassiveSubdomains)

	var PassiveSubdomains []string
	var passiveSubdomainsArray []helper.Domain

	if state.Alive || state.AquatoneJSON {
		// Nove remove all wildcard subdomains
		if state.Silent != true {
			fmt.Printf("\n\nResolving %s%d%s Unique Hosts found", helper.Info, len(validPassiveSubdomains), helper.Reset)
		}
		passiveSubdomainsArray = resolver.Resolve(state, validPassiveSubdomains)
		for _, subdomain := range passiveSubdomainsArray {
			PassiveSubdomains = append(PassiveSubdomains, subdomain.Fqdn)
		}
	} else {
		PassiveSubdomains = validPassiveSubdomains
	}

	if state.AquatoneJSON {
		if !state.Silent {
			fmt.Printf("\n\nWriting Enumeration Output To %s", state.Output)
		}

		output.WriteOutputAquatoneJSON(state, passiveSubdomainsArray)
	}

	// Sort the subdomains found alphabetically
	sort.Strings(PassiveSubdomains)

	if !state.Silent {
		fmt.Printf("\n\nTotal %s%d%s Unique subdomains found for %s\n\n", helper.Info, len(PassiveSubdomains), helper.Reset, domain)
	}

	if state.Alive || state.AquatoneJSON {
		for _, subdomain := range passiveSubdomainsArray {
			if state.Silent != true {
				fmt.Printf("\n%s\t\t%s", subdomain.IP, subdomain.Fqdn)
			} else {
				fmt.Printf("\n%s", subdomain.Fqdn)
			}
		}
	} else {
		for _, subdomain := range PassiveSubdomains {
			fmt.Println(subdomain)
		}
	}

	return PassiveSubdomains
}

//Enumerate executes passive analysis
func Enumerate(state *helper.State) []string {
	sourceConfig := new(Source)

	fmt.Printf("\n")
	if state.Sources == "all" {
		// Search all data sources
		sourceConfig.enableAll()
	} else {
		// Check data sources and create a source configuration structure
		dataSources := strings.Split(state.Sources, ",")
		sourceConfig.enable(dataSources)
	}

	if !state.Silent {
		sourceConfig.printSummary()
	}

	if state.DomainList != "" {
		// Open the wordlist file
		wordfile, err := os.Open(state.DomainList)
		if err != nil {
			return nil
		}

		scanner := bufio.NewScanner(wordfile)

		for scanner.Scan() {
			DomainList = append(DomainList, scanner.Text())
		}
	} else {
		DomainList = append(DomainList, state.Domain)
	}

	passivePool := helper.NewPool(state.Threads)
	passivePool.Run()

	// add jobs
	for _, domain := range DomainList {
		passivePool.Add(analyzeDomain, domain, state, sourceConfig, passivePool)
	}

	passivePool.Wait()

	var allSubdomains []string

	completedJobs := passivePool.Results()
	for _, job := range completedJobs {
		if job.Result != nil {
			results := job.Result.([]string)
			if state.Output != "" {
				if !state.IsJSON {
					if !state.AquatoneJSON {
						err := output.WriteOutputToFile(state, results)
						if err != nil {
							if state.Silent == true {
								fmt.Printf("\n%s-> %v%s\n", helper.Bad, err, helper.Reset)
							}
						}
					}
				}
			}

			allSubdomains = append(allSubdomains, results...)
		}
	}

	passivePool.Stop()

	// Write the output to individual files in a directory
	// TODO: group results by domain and write to directory
	// if state.OutputDir != "" {
	// 	output.WriteOutputToDir(state, allSubdomains, Domain)
	// }

	return allSubdomains
}

func analyzeDomain(args ...interface{}) interface{} {
	domain := args[0].(string)
	state := args[1].(*helper.State)
	sourceConfig := args[2].(*Source)
	passivePool := args[3].(*helper.Pool)

	foundSubdomains := discover(state, domain, sourceConfig)

	if state.Output != "" {
		if !state.IsJSON {
			if !state.AquatoneJSON {
				err := output.WriteOutputToFile(state, foundSubdomains)
				if err != nil {
					if state.Silent {
						fmt.Printf("\n%s-> %v%s\n", helper.Bad, err, helper.Reset)
					}
				}
			}
		}
	}

	if state.Recursive {
		for _, subdomain := range foundSubdomains {
			// Results will be written in next recursive iteration
			passivePool.Add(analyzeDomain, subdomain, state, sourceConfig, passivePool)
		}
	}

	return foundSubdomains
}
