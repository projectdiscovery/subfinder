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

var DomainList []string

// Sources configuration structure specifying what should we use
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

	NoOfSources int
}

func Discover(state *helper.State, domain string, sourceConfig *Source) (subdomains []string) {

	var finalPassiveSubdomains []string

	if strings.Contains(domain, "*.") {
		domain = strings.Split(domain, "*.")[1]
	}

	// Set state domain to current domain
	state.Domain = domain

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

	ch := make(chan helper.Result, sourceConfig.NoOfSources)

	if state.Silent != true {
		fmt.Printf("\nRunning enumeration on %s", domain)
	}

	// Create goroutines for added speed and recieve data via channels
	// Check if we the user has specified custom sources and if yes, run them
	// via if statements.
	if sourceConfig.Crtsh == true {
		go crtsh.Query(state, ch)
	}
	if sourceConfig.Certdb == true {
		go certdb.Query(state, ch)
	}
	if sourceConfig.Certspotter == true {
		go certspotter.Query(state, ch)
	}
	if sourceConfig.Threatcrowd == true {
		go threatcrowd.Query(state, ch)
	}
	if sourceConfig.Findsubdomains == true {
		go findsubdomains.Query(state, ch)
	}
	if sourceConfig.Dnsdumpster == true {
		go dnsdumpster.Query(state, ch)
	}
	if sourceConfig.Passivetotal == true {
		go passivetotal.Query(state, ch)
	}
	if sourceConfig.Ptrarchive == true {
		go ptrarchive.Query(state, ch)
	}
	if sourceConfig.Hackertarget == true {
		go hackertarget.Query(state, ch)
	}
	if sourceConfig.Virustotal == true {
		go virustotal.Query(state, ch)
	}
	if sourceConfig.Securitytrails == true {
		go securitytrails.Query(state, ch)
	}
	if sourceConfig.Netcraft == true {
		go netcraft.Query(state, ch)
	}
	if sourceConfig.Waybackarchive == true {
		go waybackarchive.Query(state, ch)
	}
	if sourceConfig.Threatminer == true {
		go threatminer.Query(state, ch)
	}
	if sourceConfig.Riddler == true {
		go riddler.Query(state, ch)
	}
	if sourceConfig.Censys == true {
		go censys.Query(state, ch)
	}
	if sourceConfig.Dnsdb == true {
		go dnsdb.Query(state, ch)
	}
	if sourceConfig.Baidu == true {
		go baidu.Query(state, ch)
	}
	if sourceConfig.Bing == true {
		go bing.Query(state, ch)
	}
	if sourceConfig.Ask == true {
		go ask.Query(state, ch)
	}

	// Recieve data from all goroutines running
	for i := 0; i < sourceConfig.NoOfSources; i++ {
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
	validPassiveSubdomains := helper.Validate(state, uniquePassiveSubdomains)

	var PassiveSubdomains []string
	var JobArray []*helper.Job

	if state.Alive == true || state.AquatoneJSON == true {
		// Nove remove all wildcard subdomains
		if state.Silent != true {
			fmt.Printf("\nResolving %s%d%s Unique Hosts found", helper.Info, len(validPassiveSubdomains), helper.Reset)
		}
		JobArray = resolver.Resolve(state, validPassiveSubdomains)
		for _, job := range JobArray {
			PassiveSubdomains = append(PassiveSubdomains, job.Work)
		}
	} else {
		PassiveSubdomains = validPassiveSubdomains
	}

	if state.AquatoneJSON == true {
		if state.Silent != true {
			fmt.Printf("\n\nWriting Enumeration Output To %s", state.Output)
		}

		output.WriteOutputAquatoneJSON(state, JobArray)
	}

	// Sort the subdomains found alphabetically
	sort.Strings(PassiveSubdomains)

	if state.Silent != true {
		fmt.Printf("\n\nTotal %s%d%s Unique subdomains found for %s\n\n", helper.Info, len(PassiveSubdomains), helper.Reset, domain)
	}
	if state.Alive == true || state.AquatoneJSON == true {
		for _, job := range JobArray {
			if state.Silent != true {
				fmt.Printf("\n%s\t\t%s", job.Result, job.Work)
			} else {
				fmt.Printf("\n%s", job.Work)
			}
		}
	} else {
		for _, subdomain := range PassiveSubdomains {
			fmt.Println(subdomain)
		}
	}

	return PassiveSubdomains
}
func PassiveDiscovery(state *helper.State) (finalPassiveSubdomains []string) {
	sourceConfig := Source{false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 0}

	fmt.Printf("\n")
	if state.Sources == "all" {
		// Search all data sources

		if state.Silent != true {
			fmt.Printf("\nRunning Source: %sAsk%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sBaidu%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sBing%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sCensys%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sCrt.sh%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sCertDB%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sCertspotter%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sDnsdb%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sThreatcrowd%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sFindsubdomains%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sDNSDumpster%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sPassiveTotal%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sPTRArchive%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sHackertarget%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sVirustotal%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sSecuritytrails%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sWaybackArchive%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sThreatMiner%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sRiddler%s", helper.Info, helper.Reset)
			fmt.Printf("\nRunning Source: %sNetcraft%s\n", helper.Info, helper.Reset)
		}

		sourceConfig = Source{true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, 20}
	} else {
		// Check data sources and create a source configuration structure

		dataSources := strings.Split(state.Sources, ",")
		for _, source := range dataSources {
			if source == "crtsh" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sCrt.sh%s", helper.Info, helper.Reset)
				}
				sourceConfig.Crtsh = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "certdb" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sCertDB%s", helper.Info, helper.Reset)
				}
				sourceConfig.Certdb = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "certspotter" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sCertspotter%s", helper.Info, helper.Reset)
				}
				sourceConfig.Certspotter = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "threatcrowd" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sThreatcrowd%s", helper.Info, helper.Reset)
				}
				sourceConfig.Threatcrowd = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "findsubdomains" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sFindsubdomains%s", helper.Info, helper.Reset)
				}
				sourceConfig.Findsubdomains = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "dnsdumpster" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sDNSDumpster%s", helper.Info, helper.Reset)
				}
				sourceConfig.Dnsdumpster = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "passivetotal" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sPassiveTotal%s", helper.Info, helper.Reset)
				}
				sourceConfig.Passivetotal = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "ptrarchive" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sPTRArchive%s", helper.Info, helper.Reset)
				}
				sourceConfig.Ptrarchive = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "hackertarget" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sHackertarget%s", helper.Info, helper.Reset)
				}
				sourceConfig.Hackertarget = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "virustotal" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sVirustotal%s", helper.Info, helper.Reset)
				}
				sourceConfig.Virustotal = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "securitytrails" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sSecuritytrails%s", helper.Info, helper.Reset)
				}
				sourceConfig.Securitytrails = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "netcraft" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sNetcraft%s\n", helper.Info, helper.Reset)
				}
				sourceConfig.Netcraft = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "waybackarchive" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sWaybackArchive%s", helper.Info, helper.Reset)
				}
				sourceConfig.Waybackarchive = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "threatminer" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sThreatMiner%s", helper.Info, helper.Reset)
				}
				sourceConfig.Threatminer = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "riddler" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sRiddler%s", helper.Info, helper.Reset)
				}
				sourceConfig.Riddler = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "censys" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sCensys%s", helper.Info, helper.Reset)
				}
				sourceConfig.Censys = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "dnsdb" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sDnsdb%s", helper.Info, helper.Reset)
				}
				sourceConfig.Dnsdb = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "baidu" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sBaidu%s", helper.Info, helper.Reset)
				}
				sourceConfig.Baidu = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "bing" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sBing%s", helper.Info, helper.Reset)
				}
				sourceConfig.Bing = true
			} else if source == "ask" {
				if state.Silent != true {
					fmt.Printf("\nRunning Source: %sAsk%s", helper.Info, helper.Reset)
				}
				sourceConfig.Ask = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			}
		}
	}

	fmt.Printf("\n")

	var tempResults []string
	var hostResults []string

	if state.DomainList != "" {
		// Open the wordlist file
		wordfile, err := os.Open(state.DomainList)
		if err != nil {
			return finalPassiveSubdomains
		}

		scanner := bufio.NewScanner(wordfile)

		for scanner.Scan() {
			DomainList = append(DomainList, scanner.Text())
		}
	} else {
		DomainList = append(DomainList, state.Domain)
	}

	// Perform enumeration such that even if there is a domain list, we
	// can easily reuse the same code
	for _, Domain := range DomainList {
		// Make the first run
		results := Discover(state, Domain, &sourceConfig)
		finalPassiveSubdomains = append(finalPassiveSubdomains, results...)
		hostResults = append(hostResults, results...)

		if state.Output != "" {
			if state.IsJSON != true {
				if state.AquatoneJSON != true {
					err := output.WriteOutputToFile(state, results)
					if err != nil {
						if state.Silent == true {
							fmt.Printf("\n%s-> %v%s\n", helper.Bad, err, helper.Reset)
						}
					}
				}
			}
		}

		// Perform Recursive Enumeration Here
		if state.Recursive == true {
			for _, foundSub := range results {
				tempResults = Discover(state, foundSub, &sourceConfig)
				finalPassiveSubdomains = append(finalPassiveSubdomains, tempResults...)
				hostResults = append(hostResults, tempResults...)

				// Write second round of results
				if state.Output != "" {
					if state.IsJSON != true {
						if state.AquatoneJSON != true {
							err := output.WriteOutputToFile(state, hostResults)
							if err != nil {
								if state.Silent == true {
									fmt.Printf("\n%s-> %v%s\n", helper.Bad, err, helper.Reset)
								}
							}
						}
					}
				}
			}
		}

		// Write the output to individual files in a directory
		if state.OutputDir != "" {
			output.WriteOutputToDir(state, hostResults, Domain)
		}
		// Truncate the whole array
		hostResults = nil
	}

	return finalPassiveSubdomains
}
