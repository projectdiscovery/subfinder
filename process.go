//
// process.go : Contains main package drivers and stuff
// Written By : @codingo
//		@ice3man
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package main

import (
	"flag"
	"fmt"
	"os"

	"subfinder/libsubfinder/helper"

	// Load different Passive data sources
	"subfinder/libsubfinder/sources/certspotter"
	"subfinder/libsubfinder/sources/crtsh"
	"subfinder/libsubfinder/sources/hackertarget"
	"subfinder/libsubfinder/sources/threatcrowd"
	"subfinder/libsubfinder/sources/virustotal"
	"subfinder/libsubfinder/sources/netcraft"
)

// ParseCmdLine ... Parses command line into settings
func ParseCmdLine() (state *helper.State, err error) {

	// Initialize current state and read Config file
	s, err := helper.InitState()
	if err != nil {
		return &s, err
	}

	flag.BoolVar(&s.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&s.Color, "c", true, "Use colour in outpout")
	flag.IntVar(&s.Threads, "t", 10, "Number of concurrent threads")
	flag.StringVar(&s.Domain, "d", "", "Domain to find subdomains for")
	flag.BoolVar(&s.Recursive, "r", true, "Use recursion to find subdomains")

	flag.Parse()

	// todo: add validate state code here
	return &s, nil
}

func main() {
	// todo: move this into CLI code
	fmt.Printf("\n[#] SubFinder : Subdomain Enumeration On Steroids ")
	fmt.Printf("\n[#] Written by @ice3man543 and @codingo_")
	fmt.Printf("\n[#] Website : https://0x41team.github.io\n\n")

	state, err := ParseCmdLine()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Improve Usage guide here
	if state.Domain == "" {
		fmt.Printf("subfinder: Missing domain argument\nTry './subfinder -h' for more information\n")
		os.Exit(1)
	}

	var finalPassiveSubdomains []string

	// TODO : Add Go Concurrency to requests for data sources :-)
	fmt.Printf("[-] Trying Crt.sh service from Comodo")
	crtSh, err := crtsh.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range crtSh {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	fmt.Printf("\n\n[-] Trying CertSpotter API")
	certspotterResults, err := certspotter.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range certspotterResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	fmt.Printf("\n\n[-] Trying Threatcrowd API")
	threatcrowdResults, err := threatcrowd.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range threatcrowdResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	fmt.Printf("\n\n[-] Trying Hackertarget API")
	hackertargetResults, err := hackertarget.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range hackertargetResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	fmt.Printf("\n\n[-] Trying Virustotal Domain Query")
	virustotalResults, err := virustotal.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range virustotalResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	fmt.Printf("\n\n[-] Trying Netcraft Domain Query")
	netcraftResults, err := netcraft.Query(state)
	if err != nil {
		fmt.Println(err)
	}
	for _, subdomain := range netcraftResults {
		finalPassiveSubdomains = append(finalPassiveSubdomains, subdomain)
	}

	// Now remove duplicate items from the slice
	unique_passive_subdomains := helper.Unique(finalPassiveSubdomains)
	fmt.Printf("\n\n[#] Total %d Unique subdomains found passively\n\n", len(unique_passive_subdomains))
	for _, subdomain := range unique_passive_subdomains {
		fmt.Println(subdomain)
	}
}
