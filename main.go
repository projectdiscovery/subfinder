// subfinder : Subdomain discovery tool in golang
// Written By : @codingo
//		@ice3man
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man

// Contains main driver classes for the tool
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ice3man543/subfinder/libsubfinder/engines/passive"
	"github.com/ice3man543/subfinder/libsubfinder/helper"
	"github.com/ice3man543/subfinder/libsubfinder/output"
	//"github.com/ice3man543/subfinder/libsubfinder/engines/bruteforce"
)

var banner = `
             __     ___ __          __            
.-----.--.--|  |--.'  _|__.-----.--|  .-----.----.
|__ --|  |  |  _  |   _|  |     |  _  |  -__|   _|
|_____|_____|_____|__| |__|__|__|_____|_____|__|  `

// Parses command line arguments into a setting structure
func ParseCmdLine() (state *helper.State, err error) {

	// Initialize current state and read Config file
	s, err := helper.InitState()
	if err != nil {
		return &s, err
	}

	flag.BoolVar(&s.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&s.Color, "c", true, "Use colour in outpout")
	flag.IntVar(&s.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&s.Timeout, "timeout", 180, "Timeout for passive discovery services")
	flag.StringVar(&s.Domain, "d", "", "Domain to find subdomains for")
	flag.StringVar(&s.Output, "o", "", "Name of the output file (optional)")
	flag.BoolVar(&s.IsJSON, "oJ", false, "Write output in JSON Format")
	flag.BoolVar(&s.Alive, "nw", false, "Remove Wildcard Subdomains from output")
	flag.BoolVar(&s.Silent, "silent", false, "Show only subdomains in output")
	flag.BoolVar(&s.Recursive, "r", true, "Use recursion to find subdomains")
	flag.StringVar(&s.Wordlist, "w", "", "Wordlist for doing subdomain bruteforcing")
	flag.StringVar(&s.Sources, "sources", "all", "Comma separated list of sources to use")
	flag.BoolVar(&s.Bruteforce, "b", false, "Use bruteforcing to find subdomains")
	flag.BoolVar(&s.WildcardForced, "fw", false, "Force Bruteforcing of Wildcard DNS")

	flag.Parse()

	return &s, nil
}

func main() {

	state, err := ParseCmdLine()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if state.Silent != true {
		fmt.Println(banner)
		fmt.Printf("\nSubFinder v0.1.0 	  Made with %s❤%s by @Ice3man", helper.Green, helper.Reset)
		fmt.Printf("\n==================================================")
	}

	if state.Domain == "" {
		if state.Silent != true {
			fmt.Printf("\n\nsubfinder: Missing domain argument\nTry './subfinder -h' for more information\n")
		}
		os.Exit(1)
	}

	passiveSubdomains := passive.PassiveDiscovery(state)
	if state.Output != "" {
		err := output.WriteOutputText(state, passiveSubdomains)
		if err != nil {
			if state.Silent != true {
				fmt.Printf("\nerror : %v", err)
			}
		} else {
			if state.Silent != true {
				fmt.Printf("\n[#] Successfully Written Output to File : %s\n", state.Output)
			}
		}
	}

	//bruteforce.Bruteforce(state)
}
