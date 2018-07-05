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

	"github.com/subfinder/subfinder/libsubfinder/helper"
	"github.com/subfinder/subfinder/subf"
)

// ParseCmdLine ...  Parses command line arguments into a setting structure
// ParseCmdLine ...  Parses command line arguments into a setting structure
func ParseCmdLine() (s *subf.Subfinder) {

	s = subf.NewSubfinder()

	flag.BoolVar(&s.State.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&s.State.Color, "no-color", true, "Don't Use colors in output")
	flag.IntVar(&s.State.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&s.State.Timeout, "timeout", 180, "Timeout for passive discovery services")
	flag.StringVar(&s.State.Domain, "d", "", "Domain to find subdomains for")
	flag.StringVar(&s.State.Output, "o", "", "Name of the output file (optional)")
	flag.BoolVar(&s.State.IsJSON, "oJ", false, "Write output in JSON Format")
	flag.BoolVar(&s.State.Alive, "nW", false, "Remove Wildcard Subdomains from output")
	flag.BoolVar(&s.State.NoPassive, "no-passive", false, "Do not perform passive subdomain enumeration")
	flag.BoolVar(&s.State.Silent, "silent", false, "Show only subdomains in output")
	flag.BoolVar(&s.State.Recursive, "recursive", false, "Use recursion to find subdomains")
	flag.StringVar(&s.State.Wordlist, "w", "", "Wordlist for doing subdomain bruteforcing")
	flag.StringVar(&s.State.Sources, "sources", "all", "Comma separated list of sources to use")
	flag.BoolVar(&s.State.Bruteforce, "b", false, "Use bruteforcing to find subdomains")
	flag.StringVar(&s.State.SetConfig, "set-config", "none", "Comma separated list of configuration details")
	flag.StringVar(&s.State.SetSetting, "set-settings", "none", "Comma separated list of settings")
	flag.StringVar(&s.State.DomainList, "dL", "", "List of domains to find subdomains for")
	flag.StringVar(&s.State.OutputDir, "oD", "", "Directory to output results to ")
	flag.StringVar(&s.State.ComResolver, "r", "", "Comma-separated list of resolvers to use")
	flag.StringVar(&s.State.ListResolver, "rL", "", "Text file containing list of resolvers to use")
	flag.StringVar(&s.State.ExcludeSource, "exclude-sources", "", "List of sources to exclude from enumeration")
	flag.BoolVar(&s.State.AquatoneJSON, "oT", false, "Use aquatone style json output format")
	flag.Parse()

	return s
}

func main() {

	subfinder := ParseCmdLine()

	if !subfinder.State.Silent {
		fmt.Println("===============================================")
		fmt.Printf("%s%s-=Subfinder%s v1.1.3 github.com/subfinder/subfinder\n", helper.Info, helper.Cyan, helper.Reset)
		fmt.Println("===============================================")
	}

	subfinder.Init()

	_ = subfinder.PassiveEnumeration()

	fmt.Printf("\n")
}
