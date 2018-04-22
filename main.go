// subfinder : Subdomain discovery tool in golang
// Written By : @codingo
//		@ice3man
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man

// Contains main driver classes for the tool
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"

	"github.com/ice3man543/subfinder/libsubfinder/engines/passive"
	"github.com/ice3man543/subfinder/libsubfinder/helper"
	"github.com/ice3man543/subfinder/libsubfinder/output"
	//"github.com/ice3man543/subfinder/libsubfinder/engines/bruteforce"
)

var banner = `
   ____     __   _____         __       
  / __/_ __/ /  / __(_)__  ___/ /__ ____
 _\ \/ // / _ \/ _// / _ \/ _  / -_) __/
/___/\_,_/_.__/_/ /_/_//_/\_,_/\__/_/   
                                      `

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
	flag.StringVar(&s.SetConfig, "set-config", "none", "Comma separated list of configuration details")

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
		fmt.Printf("\n==================================================\n")
	}

	if state.SetConfig != "none" {
		setConfig := strings.Split(state.SetConfig, ",")

		// Build Configuration path
		home := helper.GetHomeDir()
		path := home + "/.config/subfinder/config.json"

		for _, config := range setConfig {
			object := strings.Split(config, "=")

			// Change value dynamically using reflect package
			reflect.ValueOf(&state.ConfigState).Elem().FieldByName(object[0]).SetString(object[1])
			configJson, _ := json.MarshalIndent(state.ConfigState, "", "	")
			err = ioutil.WriteFile(path, configJson, 0644)
			if err != nil {
				fmt.Printf("\n\n[!] Error : %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("[-] Successfully configured %s=>%s\n", object[0], object[1])
		}

		os.Exit(0)
	}

	if state.Domain == "" {
		if state.Silent != true {
			fmt.Printf("\n\nsubfinder: Missing domain argument\nTry './subfinder -h' for more information\n")
		}
		os.Exit(1)
	}

	passiveSubdomains := passive.PassiveDiscovery(state)
	if state.Output != "" {
		if state.IsJSON == true {
			err := output.WriteOutputJSON(state, passiveSubdomains)
			if err != nil {
				if state.Silent != true {
					fmt.Printf("\nerror : %v", err)
				}
			} else {
				if state.Silent != true {
					fmt.Printf("\n[#] Successfully Written Output to File : %s\n", state.Output)
				}
			}
		} else {
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
	}

	//bruteforce.Bruteforce(state)
}
