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
	Censys         bool
	Certdb         bool
	Crtsh          bool
	Certspotter    bool
	Threatcrowd    bool
	Findsubdomains bool
	Dnsdumpster    bool
	Passivetotal   bool
	Ptrarchive     bool
	Hackertarget   bool
	Virustotal     bool
	Securitytrails bool
	Netcraft       bool
	Waybackarchive bool
	Threatminer    bool
	Riddler        bool
	Dnsdb          bool
	Baidu          bool
	Bing           bool
	Ask            bool
}

func (s *Source) enableAll() {
	s.Censys = true
	s.Certdb = true
	s.Crtsh = true
	s.Certspotter = true
	s.Threatcrowd = true
	s.Findsubdomains = true
	s.Dnsdumpster = true
	s.Passivetotal = true
	s.Ptrarchive = true
	s.Hackertarget = true
	s.Virustotal = true
	s.Securitytrails = true
	s.Netcraft = true
	s.Waybackarchive = true
	s.Threatminer = true
	s.Riddler = true
	s.Dnsdb = true
	s.Baidu = true
	s.Bing = true
	s.Ask = true
}

func (s *Source) enable(dataSources []string) {
	for _, source := range dataSources {
		switch source {
		case "crtsh":
			s.Crtsh = true
		case "certdb":
			s.Certdb = true
		case "certspotter":
			s.Certspotter = true
		case "threatcrowd":
			s.Threatcrowd = true
		case "findsubdomains":
			s.Findsubdomains = true
		case "dnsdumpster":
			s.Dnsdumpster = true
		case "passivetotal":
			s.Passivetotal = true
		case "ptrarchive":
			s.Ptrarchive = true
		case "hackertarget":
			s.Hackertarget = true
		case "virustotal":
			s.Virustotal = true
		case "securitytrails":
			s.Securitytrails = true
		case "netcraft":
			s.Netcraft = true
		case "waybackarchive":
			s.Waybackarchive = true
		case "threatminer":
			s.Threatminer = true
		case "riddler":
			s.Riddler = true
		case "censys":
			s.Censys = true
		case "dnsdb":
			s.Dnsdb = true
		case "baidu":
			s.Baidu = true
		case "bing":
			s.Bing = true
		case "ask":
			s.Ask = true
		}
	}
}

func (s *Source) printSummary() {
	if s.Crtsh {
		fmt.Printf("\nRunning Source: %sCrt.sh%s", helper.Info, helper.Reset)
	}
	if s.Certdb {
		fmt.Printf("\nRunning Source: %sCertDB%s", helper.Info, helper.Reset)
	}
	if s.Certspotter {
		fmt.Printf("\nRunning Source: %sCertspotter%s", helper.Info, helper.Reset)
	}
	if s.Threatcrowd {
		fmt.Printf("\nRunning Source: %sThreatcrowd%s", helper.Info, helper.Reset)
	}
	if s.Findsubdomains {
		fmt.Printf("\nRunning Source: %sFindsubdomains%s", helper.Info, helper.Reset)
	}
	if s.Dnsdumpster {
		fmt.Printf("\nRunning Source: %sDNSDumpster%s", helper.Info, helper.Reset)
	}
	if s.Passivetotal {
		fmt.Printf("\nRunning Source: %sPassiveTotal%s", helper.Info, helper.Reset)
	}
	if s.Ptrarchive {
		fmt.Printf("\nRunning Source: %sPTRArchive%s", helper.Info, helper.Reset)
	}
	if s.Hackertarget {
		fmt.Printf("\nRunning Source: %sHackertarget%s", helper.Info, helper.Reset)
	}
	if s.Virustotal {
		fmt.Printf("\nRunning Source: %sVirustotal%s", helper.Info, helper.Reset)
	}
	if s.Securitytrails {
		fmt.Printf("\nRunning Source: %sSecuritytrails%s", helper.Info, helper.Reset)
	}
	if s.Netcraft {
		fmt.Printf("\nRunning Source: %sNetcraft%s\n", helper.Info, helper.Reset)
	}
	if s.Waybackarchive {
		fmt.Printf("\nRunning Source: %sWaybackArchive%s", helper.Info, helper.Reset)
	}
	if s.Threatminer {
		fmt.Printf("\nRunning Source: %sThreatMiner%s", helper.Info, helper.Reset)
	}
	if s.Riddler {
		fmt.Printf("\nRunning Source: %sRiddler%s", helper.Info, helper.Reset)
	}
	if s.Censys {
		fmt.Printf("\nRunning Source: %sCensys%s", helper.Info, helper.Reset)
	}
	if s.Dnsdb {
		fmt.Printf("\nRunning Source: %sDnsdb%s", helper.Info, helper.Reset)
	}
	if s.Baidu {
		fmt.Printf("\nRunning Source: %sBaidu%s", helper.Info, helper.Reset)
	}
	if s.Bing {
		fmt.Printf("\nRunning Source: %sBing%s", helper.Info, helper.Reset)
	}
	if s.Ask {
		fmt.Printf("\nRunning Source: %sAsk%s", helper.Info, helper.Reset)
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

	ch := make(chan helper.Result, sourceConfig.nbrActive())

	if state.Silent != true {
		fmt.Printf("\nRunning enumeration on %s", domain)
	}

	// Create goroutines for added speed and recieve data via channels
	// Check if we the user has specified custom sources and if yes, run them
	// via if statements.
	if sourceConfig.Crtsh == true {
		go crtsh.Query(domain, state, ch)
	}
	if sourceConfig.Certdb == true {
		go certdb.Query(domain, state, ch)
	}
	if sourceConfig.Certspotter == true {
		go certspotter.Query(domain, state, ch)
	}
	if sourceConfig.Threatcrowd == true {
		go threatcrowd.Query(domain, state, ch)
	}
	if sourceConfig.Findsubdomains == true {
		go findsubdomains.Query(domain, state, ch)
	}
	if sourceConfig.Dnsdumpster == true {
		go dnsdumpster.Query(domain, state, ch)
	}
	if sourceConfig.Passivetotal == true {
		go passivetotal.Query(domain, state, ch)
	}
	if sourceConfig.Ptrarchive == true {
		go ptrarchive.Query(domain, state, ch)
	}
	if sourceConfig.Hackertarget == true {
		go hackertarget.Query(domain, state, ch)
	}
	if sourceConfig.Virustotal == true {
		go virustotal.Query(domain, state, ch)
	}
	if sourceConfig.Securitytrails == true {
		go securitytrails.Query(domain, state, ch)
	}
	if sourceConfig.Netcraft == true {
		go netcraft.Query(domain, state, ch)
	}
	if sourceConfig.Waybackarchive == true {
		go waybackarchive.Query(domain, state, ch)
	}
	if sourceConfig.Threatminer == true {
		go threatminer.Query(domain, state, ch)
	}
	if sourceConfig.Riddler == true {
		go riddler.Query(domain, state, ch)
	}
	if sourceConfig.Censys == true {
		go censys.Query(domain, state, ch)
	}
	if sourceConfig.Dnsdb == true {
		go dnsdb.Query(domain, state, ch)
	}
	if sourceConfig.Baidu == true {
		go baidu.Query(domain, state, ch)
	}
	if sourceConfig.Bing == true {
		go bing.Query(domain, state, ch)
	}
	if sourceConfig.Ask == true {
		go ask.Query(domain, state, ch)
	}

	// Recieve data from all goroutines running
	for i := 0; i < sourceConfig.nbrActive(); i++ {
		result := <-ch

		if result.Error != nil {
			// some error occured
			if state.Silent != true {
				fmt.Printf("\nerror: %v\n", result.Error)
			}
		}
		for _, subdomain := range result.Subdomains {
			finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
		}
	}

	// Now remove duplicate items from the slice
	uniquePassiveSubdomains := helper.Unique(finalPassiveSubdomains)
	// Now, validate all subdomains found
	validPassiveSubdomains := helper.Validate(domain, uniquePassiveSubdomains)

	var PassiveSubdomains []string
	var passiveSubdomainsArray []helper.Domain

	if state.Alive || state.AquatoneJSON {
		// Nove remove all wildcard subdomains
		passiveSubdomainsArray = resolver.Resolve(state, validPassiveSubdomains)
		for _, subdomain := range passiveSubdomainsArray {
			PassiveSubdomains = append(PassiveSubdomains, subdomain.Fqdn)
		}
		if state.Silent != true {
			fmt.Printf("\nResolving %s%d%s Unique Hosts found", helper.Info, len(validPassiveSubdomains), helper.Reset)
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
