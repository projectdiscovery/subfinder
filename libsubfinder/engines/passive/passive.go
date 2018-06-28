//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man

// Package passive is the main core of the program
package passive

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/bogdanovich/dns_resolver"

	"github.com/subfinder/subfinder/libsubfinder/engines/bruteforce"
	"github.com/subfinder/subfinder/libsubfinder/engines/resolver"
	"github.com/subfinder/subfinder/libsubfinder/helper"
	"github.com/subfinder/subfinder/libsubfinder/output"

	// Load different Passive data sources
	"github.com/subfinder/subfinder/libsubfinder/sources/archiveis"
	"github.com/subfinder/subfinder/libsubfinder/sources/ask"
	"github.com/subfinder/subfinder/libsubfinder/sources/baidu"
	"github.com/subfinder/subfinder/libsubfinder/sources/bing"
	"github.com/subfinder/subfinder/libsubfinder/sources/censys"
	"github.com/subfinder/subfinder/libsubfinder/sources/certdb"
	"github.com/subfinder/subfinder/libsubfinder/sources/certificatetransparency"
	"github.com/subfinder/subfinder/libsubfinder/sources/certspotter"
	"github.com/subfinder/subfinder/libsubfinder/sources/crtsh"
	"github.com/subfinder/subfinder/libsubfinder/sources/dnsdb"
	"github.com/subfinder/subfinder/libsubfinder/sources/dnsdumpster"
	"github.com/subfinder/subfinder/libsubfinder/sources/dogpile"
	"github.com/subfinder/subfinder/libsubfinder/sources/exalead"
	"github.com/subfinder/subfinder/libsubfinder/sources/findsubdomains"
	"github.com/subfinder/subfinder/libsubfinder/sources/googleter"
	"github.com/subfinder/subfinder/libsubfinder/sources/hackertarget"
	"github.com/subfinder/subfinder/libsubfinder/sources/ipv4info"
	"github.com/subfinder/subfinder/libsubfinder/sources/netcraft"
	"github.com/subfinder/subfinder/libsubfinder/sources/passivetotal"
	"github.com/subfinder/subfinder/libsubfinder/sources/ptrarchive"
	"github.com/subfinder/subfinder/libsubfinder/sources/riddler"
	"github.com/subfinder/subfinder/libsubfinder/sources/securitytrails"
	"github.com/subfinder/subfinder/libsubfinder/sources/shodan"
	"github.com/subfinder/subfinder/libsubfinder/sources/sitedossier"
	"github.com/subfinder/subfinder/libsubfinder/sources/sslcertificates"
	"github.com/subfinder/subfinder/libsubfinder/sources/threatcrowd"
	"github.com/subfinder/subfinder/libsubfinder/sources/threatminer"
	"github.com/subfinder/subfinder/libsubfinder/sources/virustotal"
	"github.com/subfinder/subfinder/libsubfinder/sources/waybackarchive"
	"github.com/subfinder/subfinder/libsubfinder/sources/yahoo"
)

//DomainList contain the list of domains
var DomainList []string

// Source configuration structure specifying what should we use
// to do passive subdomain discovery.
type Source struct {
	Ask                     bool
	Archiveis               bool
	Baidu                   bool
	Bing                    bool
	Censys                  bool
	Certdb                  bool
	Crtsh                   bool
	Certspotter             bool
	Dnsdb                   bool
	Dnsdumpster             bool
	Findsubdomains          bool
	Googleter               bool
	Hackertarget            bool
	Netcraft                bool
	Passivetotal            bool
	Ptrarchive              bool
	Riddler                 bool
	Securitytrails          bool
	SSLCertificates         bool
	Sitedossier             bool
	Threatcrowd             bool
	Threatminer             bool
	Virustotal              bool
	Waybackarchive          bool
	CertificateTransparency bool
	Ipv4Info                bool
	Yahoo                   bool
	Dogpile                 bool
	Exalead                 bool
	Shodan                  bool
}

func (s *Source) enableAll() {
	s.Ask = true
	s.Archiveis = true
	s.Baidu = true
	s.Bing = true
	s.Censys = true
	s.Certdb = true
	s.Certspotter = true
	s.Crtsh = true
	s.Dnsdb = true
	s.Dnsdumpster = true
	s.Findsubdomains = true
	s.Googleter = true
	s.Hackertarget = true
	s.Netcraft = true
	s.Passivetotal = true
	s.Ptrarchive = true
	s.Riddler = true
	s.Securitytrails = true
	s.SSLCertificates = true
	s.Sitedossier = true
	s.Threatcrowd = true
	s.Threatminer = true
	s.Virustotal = true
	s.Waybackarchive = true
	s.CertificateTransparency = true
	s.Ipv4Info = true
	s.Yahoo = true
	s.Dogpile = true
	s.Exalead = true
	s.Shodan = true
}

func (s *Source) enable(dataSources []string) {
	for _, source := range dataSources {
		switch source {
		case "ask":
			s.Ask = true
		case "archiveis":
			s.Archiveis = true
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
		case "googleter":
			s.Googleter = true
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
		case "sslcertificates":
			s.SSLCertificates = true
		case "sitedossier":
			s.Sitedossier = true
		case "threatcrowd":
			s.Threatcrowd = true
		case "threatminer":
			s.Threatminer = true
		case "virustotal":
			s.Virustotal = true
		case "waybackarchive":
			s.Waybackarchive = true
		case "certificatetransparency":
			s.CertificateTransparency = true
		case "ipv4info":
			s.Ipv4Info = true
		case "yahoo":
			s.Yahoo = true
		case "dogpile":
			s.Dogpile = true
		case "exalead":
			s.Exalead = true
		case "shodan":
			s.Shodan = true
		}
	}
}

func (s *Source) disable(dataSources []string) {
	for _, source := range dataSources {
		switch source {
		case "ask":
			s.Ask = false
		case "archiveis":
			s.Archiveis = false
		case "baidu":
			s.Baidu = false
		case "bing":
			s.Bing = false
		case "censys":
			s.Censys = false
		case "certdb":
			s.Certdb = false
		case "certspotter":
			s.Certspotter = false
		case "crtsh":
			s.Crtsh = false
		case "dnsdb":
			s.Dnsdb = false
		case "dnsdumpster":
			s.Dnsdumpster = false
		case "findsubdomains":
			s.Findsubdomains = false
		case "googleter":
			s.Googleter = false
		case "hackertarget":
			s.Hackertarget = false
		case "netcraft":
			s.Netcraft = false
		case "passivetotal":
			s.Passivetotal = false
		case "ptrarchive":
			s.Ptrarchive = false
		case "riddler":
			s.Riddler = false
		case "securitytrails":
			s.Securitytrails = false
		case "sslcertificates":
			s.SSLCertificates = false
		case "sitedossier":
			s.Sitedossier = false
		case "threatcrowd":
			s.Threatcrowd = false
		case "threatminer":
			s.Threatminer = false
		case "virustotal":
			s.Virustotal = false
		case "waybackarchive":
			s.Waybackarchive = false
		case "certificatetransparency":
			s.CertificateTransparency = false
		case "ipv4info":
			s.Ipv4Info = false
		case "yahoo":
			s.Yahoo = false
		case "dogpile":
			s.Dogpile = false
		case "exalead":
			s.Dogpile = false
		case "shodan":
			s.Shodan = false
		case "all":
			s.Ask = false
			s.Archiveis = false
			s.Baidu = false
			s.Bing = false
			s.Censys = false
			s.Certdb = false
			s.Certspotter = false
			s.Crtsh = false
			s.Dnsdb = false
			s.Dnsdumpster = false
			s.Findsubdomains = false
			s.Googleter = false
			s.Hackertarget = false
			s.Netcraft = false
			s.Passivetotal = false
			s.Ptrarchive = false
			s.Riddler = false
			s.Securitytrails = false
			s.SSLCertificates = false
			s.Sitedossier = false
			s.Threatcrowd = false
			s.Threatminer = false
			s.Virustotal = false
			s.Waybackarchive = false
			s.CertificateTransparency = false
			s.Ipv4Info = false
			s.Exalead = false
			s.Yahoo = false
			s.Dogpile = false
			s.Dogpile = false
			s.Shodan = false
		}
	}
}

func (s *Source) printSummary() {
	if s.Ask {
		fmt.Printf("\nRunning Source: %sAsk%s", helper.Info, helper.Reset)
	}
	if s.Archiveis {
		fmt.Printf("\nRunning Source: %sArchive.is%s", helper.Info, helper.Reset)
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
	if s.CertificateTransparency {
		fmt.Printf("\nRunning Source: %sCertificateTransparency%s", helper.Info, helper.Reset)
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
	if s.Dogpile {
		fmt.Printf("\nRunning Source: %sDogpile%s", helper.Info, helper.Reset)
	}
	if s.Exalead {
		fmt.Printf("\nRunning Source: %sExalead%s", helper.Info, helper.Reset)
	}
	if s.Findsubdomains {
		fmt.Printf("\nRunning Source: %sFindsubdomains%s", helper.Info, helper.Reset)
	}
	if s.Googleter {
		fmt.Printf("\nRunning Source: %sGoogleter%s", helper.Info, helper.Reset)
	}
	if s.Hackertarget {
		fmt.Printf("\nRunning Source: %sHackertarget%s", helper.Info, helper.Reset)
	}
	if s.Ipv4Info {
		fmt.Printf("\nRunning Source: %sIpv4Info%s", helper.Info, helper.Reset)
	}
	if s.Netcraft {
		fmt.Printf("\nRunning Source: %sNetcraft%s", helper.Info, helper.Reset)
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
	if s.SSLCertificates {
		fmt.Printf("\nRunning Source: %sSSLCertificates%s", helper.Info, helper.Reset)
	}
	if s.Shodan {
		fmt.Printf("\nRunning Source: %sShodan%s", helper.Info, helper.Reset)
	}
	if s.Sitedossier {
		fmt.Printf("\nRunning Source: %sSitedossier%s", helper.Info, helper.Reset)
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
	if s.Yahoo {
		fmt.Printf("\nRunning Source: %sYahoo%s\n", helper.Info, helper.Reset)
	}

}

func (s *Source) parseAPIKeys(state *helper.State) {
	if state.ConfigState.CensysUsername == "" && state.ConfigState.CensysSecret == "" {
		s.Censys = false
	}
	if state.ConfigState.PassivetotalUsername == "" && state.ConfigState.PassivetotalKey == "" {
		s.Passivetotal = false
	}
	if state.ConfigState.RiddlerEmail == "" && state.ConfigState.RiddlerPassword == "" {
		s.Riddler = false
	}
	if state.ConfigState.SecurityTrailsKey == "" {
		s.Securitytrails = false
	}
	if state.ConfigState.ShodanAPIKey == "" {
		s.Shodan = false
	}
	if state.ConfigState.VirustotalAPIKey == "" {
		s.Virustotal = false
	}
	if state.ConfigState.VirustotalAPIKey == "" {
		s.Virustotal = false
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
	if state.IsWildcard {
		if !state.Silent {
			fmt.Printf("\nFound Wildcard DNS at %s", domain)
			for _, ip := range state.WildcardIP {
				fmt.Printf("\n - %s", ip)
			}
		}
	}

	domainDiscoverPool := helper.NewPool(sourceConfig.nbrActive())
	domainDiscoverPool.Run()

	domainDiscoverPool.Wait()

	if !state.Silent {
		fmt.Printf("\nRunning enumeration on %s\n", domain)
	}

	// Create goroutines for added speed and receive data via channels
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
	if sourceConfig.CertificateTransparency {
		domainDiscoverPool.Add(certificatetransparency.Query, domain, state)
	}
	if sourceConfig.Ipv4Info {
		domainDiscoverPool.Add(ipv4info.Query, domain, state)
	}
	if sourceConfig.Archiveis {
		domainDiscoverPool.Add(archiveis.Query, domain, state)
	}
	if sourceConfig.Sitedossier {
		domainDiscoverPool.Add(sitedossier.Query, domain, state)
	}
	if sourceConfig.Yahoo {
		domainDiscoverPool.Add(yahoo.Query, domain, state)
	}
	if sourceConfig.Dogpile {
		domainDiscoverPool.Add(dogpile.Query, domain, state)
	}
	if sourceConfig.Exalead {
		domainDiscoverPool.Add(exalead.Query, domain, state)
	}
	if sourceConfig.Shodan {
		domainDiscoverPool.Add(shodan.Query, domain, state)
	}
	if sourceConfig.SSLCertificates {
		domainDiscoverPool.Add(sslcertificates.Query, domain, state)
	}
	if sourceConfig.Googleter {
		domainDiscoverPool.Add(googleter.Query, domain, state)
	}

	domainDiscoverPool.Wait()

	completedJobs := domainDiscoverPool.Results()
	for _, job := range completedJobs {
		if job.Err != nil {
			// an error occurred
			if !state.Silent {
				fmt.Printf("\nerror: %v\n", job.Err)
			}
		}
		results := job.Result.([]string)
		finalPassiveSubdomains = append(finalPassiveSubdomains, results...)
	}

	domainDiscoverPool.Stop()

	// Now remove duplicate items from the slice
	uniquePassiveSubdomains := helper.Unique(finalPassiveSubdomains)
	// Now, validate all subdomains found
	validPassiveSubdomains := helper.Validate(domain, uniquePassiveSubdomains)

	var words []string
	var BruteforceSubdomainList []string
	// Start the bruteforcing workflow if the user has asked for it
	if state.Bruteforce && state.Wordlist != "" {
		file, err := os.Open(state.Wordlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			os.Exit(1)
		}

		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			// Send the job to the channel
			words = append(words, scanner.Text())
		}

		if !state.Silent {
			fmt.Printf("\n\nStarting Bruteforcing of %s%s%s with %s%d%s words", helper.Info, domain, helper.Reset, helper.Info, len(words), helper.Reset)
		}

		BruteforceSubdomainsArray := bruteforce.Brute(state, words, domain)
		for _, subdomain := range BruteforceSubdomainsArray {
			BruteforceSubdomainList = append(BruteforceSubdomainList, subdomain.Fqdn)
		}
	}

	// Append bruteforced subdomains to validPassiveSubdomains
	validPassiveSubdomains = append(validPassiveSubdomains, BruteforceSubdomainList...)

	var PassiveSubdomains []string
	var passiveSubdomainsArray []helper.Domain

	if state.Alive || state.AquatoneJSON {
		// Nove remove all wildcard subdomains
		if !state.Silent {
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
			fmt.Printf("\n\nWriting Resolved Enumeration Output To %s", state.Output)
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
			if !state.Silent {
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
		sourceConfig.enableAll()
	} else {
		// Check data sources and create a source configuration structure
		dataSources := strings.Split(state.Sources, ",")
		sourceConfig.enable(dataSources)
	}

	if state.ExcludeSource != "" {
		dataSources := strings.Split(state.ExcludeSource, ",")
		sourceConfig.disable(dataSources)
	}

	// Do not perform passive enumeration
	if state.NoPassive {
		sourceConfig.disable([]string{"all"})
	}

	// Remove sources having no API keys present for them
	sourceConfig.parseAPIKeys(state)

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
				if state.IsJSON {
					err := output.WriteOutputJSON(state, results)
					if err != nil {
						if state.Silent {
							fmt.Printf("\n%s-> %v%s\n", helper.Bad, err, helper.Reset)
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
				err := output.WriteOutputTextArray(state, foundSubdomains)
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
