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
	"fmt"
	"sort"
	"strings"

	"github.com/ice3man543/subfinder/libsubfinder/helper"

	// Load different Passive data sources
	"github.com/ice3man543/subfinder/libsubfinder/sources/certdb"
	"github.com/ice3man543/subfinder/libsubfinder/sources/certspotter"
	"github.com/ice3man543/subfinder/libsubfinder/sources/crtsh"
	"github.com/ice3man543/subfinder/libsubfinder/sources/dnsdumpster"
	"github.com/ice3man543/subfinder/libsubfinder/sources/findsubdomains"
	"github.com/ice3man543/subfinder/libsubfinder/sources/hackertarget"
	"github.com/ice3man543/subfinder/libsubfinder/sources/netcraft"
	"github.com/ice3man543/subfinder/libsubfinder/sources/passivetotal"
	"github.com/ice3man543/subfinder/libsubfinder/sources/ptrarchive"
	"github.com/ice3man543/subfinder/libsubfinder/sources/securitytrails"
	"github.com/ice3man543/subfinder/libsubfinder/sources/threatcrowd"
	"github.com/ice3man543/subfinder/libsubfinder/sources/virustotal"
)

// Sources configuration structure specifying what should we use
// to do passive subdomain discovery.
type Source struct {
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

	NoOfSources int
}

func PassiveDiscovery(state *helper.State) (finalPassiveSubdomains []string) {
	sourceConfig := Source{false, false, false, false, false, false, false, false, false, false, false, false, 0}

	fmt.Printf("\n")
	if state.Sources == "all" {
		// Search all data sources

		if state.Silent != true {
			fmt.Printf("\n[-] Searching For Subdomains in CertDB")
			fmt.Printf("\n[-] Searching For Subdomains in Certspotter")
			fmt.Printf("\n[-] Searching For Subdomains in Threatcrowd")
			fmt.Printf("\n[-] Searching For Subdomains in Findsubdomains")
			fmt.Printf("\n[-] Searching For Subdomains in DNSDumpster")
			fmt.Printf("\n[-] Searching For Subdomains in PassiveTotal")
			fmt.Printf("\n[-] Searching For Subdomains in PTRArchive")
			fmt.Printf("\n[-] Searching For Subdomains in Hackertarget")
			fmt.Printf("\n[-] Searching For Subdomains in Virustotal")
			fmt.Printf("\n[-] Searching For Subdomains in Securitytrails")
			fmt.Printf("\n[-] Searching For Subdomains in Netcraft\n")
		}

		sourceConfig = Source{true, true, true, true, true, true, true, true, true, true, true, true, 12}
	} else {
		// Check data sources and create a source configuration structure

		dataSources := strings.Split(state.Sources, ",")
		for _, source := range dataSources {
			if source == "crtsh" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Crt.sh")
				}
				sourceConfig.Crtsh = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "certdb" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in CertDB")
				}
				sourceConfig.Certdb = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "certspotter" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Certspotter")
				}
				sourceConfig.Certspotter = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "threatcrowd" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Threatcrowd")
				}
				sourceConfig.Threatcrowd = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "findsubdomains" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Findsubdomains")
				}
				sourceConfig.Findsubdomains = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "dnsdumpster" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in DNSDumpster")
				}
				sourceConfig.Dnsdumpster = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "passivetotal" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in PassiveTotal")
				}
				sourceConfig.Passivetotal = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "ptrarchive" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in PTRArchive")
				}
				sourceConfig.Ptrarchive = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "hackertarget" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Hackertarget")
				}
				sourceConfig.Hackertarget = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "virustotal" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Virustotal")
				}
				sourceConfig.Virustotal = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "securitytrails" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Securitytrails")
				}
				sourceConfig.Securitytrails = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			} else if source == "netcraft" {
				if state.Silent != true {
					fmt.Printf("\n[-] Searching For Subdomains in Netcraft")
				}
				sourceConfig.Netcraft = true
				sourceConfig.NoOfSources = sourceConfig.NoOfSources + 1
			}
		}
	}

	ch := make(chan helper.Result, sourceConfig.NoOfSources)

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

	if state.Alive == true {
		// Nove remove all wildcard subdomains
		PassiveSubdomains = helper.RemoveWildcardSubdomains(state, validPassiveSubdomains)
	}

	PassiveSubdomains = validPassiveSubdomains

	// Sort the subdomains found alphabetically
	sort.Strings(PassiveSubdomains)

	if state.Silent != true {
		fmt.Printf("\n\n[#] Total %d Unique subdomains found passively\n\n", len(PassiveSubdomains))
	}
	for _, subdomain := range PassiveSubdomains {
		fmt.Println(subdomain)
	}

	return PassiveSubdomains
}
