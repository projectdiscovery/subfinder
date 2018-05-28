// subfinder : Subdomain discovery tool in golang
// Written By : @codingo
//		@ice3man
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man

// Contains main driver classes for the tool
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Ice3man543/subfinder/libsubfinder/engines/passive"
	"github.com/Ice3man543/subfinder/libsubfinder/helper"
	//"github.com/Ice3man543/subfinder/libsubfinder/engines/bruteforce"
)

var banner = `
               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/       
                             v0.2 - by @ice3man `

// Parses command line arguments into a setting structure
func ParseCmdLine() (state *helper.State, err error) {

	// Initialize current state and read Config file
	s, err := helper.InitState()
	if err != nil {
		return &s, err
	}

	flag.BoolVar(&s.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&s.Color, "no-color", true, "Don't Use colors in output")
	flag.IntVar(&s.Threads, "t", 10, "Number of concurrent threads")
	flag.IntVar(&s.Timeout, "timeout", 180, "Timeout for passive discovery services")
	flag.StringVar(&s.Domain, "d", "", "Domain to find subdomains for")
	flag.StringVar(&s.Output, "o", "", "Name of the output file (optional)")
	flag.BoolVar(&s.IsJSON, "oJ", false, "Write output in JSON Format")
	flag.BoolVar(&s.Alive, "nW", false, "Remove Wildcard Subdomains from output")
	flag.BoolVar(&s.Silent, "silent", false, "Show only subdomains in output")
	flag.BoolVar(&s.Recursive, "recursive", false, "Use recursion to find subdomains")
	flag.StringVar(&s.Wordlist, "w", "", "Wordlist for doing subdomain bruteforcing")
	flag.StringVar(&s.Sources, "sources", "all", "Comma separated list of sources to use")
	flag.BoolVar(&s.Bruteforce, "b", false, "Use bruteforcing to find subdomains")
	flag.StringVar(&s.SetConfig, "set-config", "none", "Comma separated list of configuration details")
	flag.StringVar(&s.SetSetting, "set-settings", "none", "Comma separated list of settings")
	flag.StringVar(&s.DomainList, "dL", "", "List of domains to find subdomains for")
	flag.StringVar(&s.OutputDir, "oD", "", "Directory to output results to ")
	flag.StringVar(&s.ComResolver, "r", "", "Comma-separated list of resolvers to use")
	flag.StringVar(&s.ListResolver, "rL", "", "Text file containing list of resolvers to use")
	flag.BoolVar(&s.AquatoneJSON, "oT", false, "Use aquatone style json output format")
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
	}

	if state.SetConfig != "none" {
		setConfig := strings.Split(state.SetConfig, ",")

		// Build Configuration path
		home := helper.GetHomeDir()
		path := home + "/.config/subfinder/config.json"

		for _, config := range setConfig {
			object := strings.Split(config, "=")

			// Change value dynamically using reflect package
			if strings.EqualFold(object[0], "virustotalapikey") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("VirustotalAPIKey").SetString(object[1])
			} else if strings.EqualFold(object[0], "passivetotalusername") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("PassivetotalUsername").SetString(object[1])
			} else if strings.EqualFold(object[0], "passivetotalkey") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("PassivetotalKey").SetString(object[1])
			} else if strings.EqualFold(object[0], "securitytrailskey") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("SecurityTrailsKey").SetString(object[1])
			} else if strings.EqualFold(object[0], "riddleremail") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("RiddlerEmail").SetString(object[1])
			} else if strings.EqualFold(object[0], "riddlerpassword") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("RiddlerPassword").SetString(object[1])
			} else if strings.EqualFold(object[0], "censysusername") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("CensysUsername").SetString(object[1])
			} else if strings.EqualFold(object[0], "censyssecret") == true {
				reflect.ValueOf(&state.ConfigState).Elem().FieldByName("CensysSecret").SetString(object[1])
			}

			configJson, _ := json.MarshalIndent(state.ConfigState, "", "	")
			err = ioutil.WriteFile(path, configJson, 0644)
			if err != nil {
				fmt.Printf("\n\n[!] Error : %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Successfully configured %s%s%s=>%s\n", helper.Info, object[0], helper.Reset, object[1])
		}

		os.Exit(0)
	}

	if state.SetSetting != "none" {
		setSetting := strings.Split(state.SetSetting, ",")

		for _, setting := range setSetting {
			object := strings.Split(setting, "=")

			// Change value dynamically using reflect package
			reflect.ValueOf(&state.CurrentSettings).Elem().FieldByName(object[0]).SetString(object[1])
			if state.Silent != true {
				if state.Verbose == true {
					fmt.Printf("Successfully Set %s%s%s=>%s\n", helper.Info, object[0], helper.Reset, object[1])
				}
			}
		}
	}

	if state.ComResolver != "" {
		// Load the Resolvers from list
		setResolvers := strings.Split(state.ComResolver, ",")

		for _, resolver := range setResolvers {
			state.LoadResolver = append(state.LoadResolver, resolver)
		}
	}

	if state.ListResolver != "" {
		// Load the resolvers from file
		file, err := os.Open(state.ListResolver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
			os.Exit(1)
		}

		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			// Send the job to the channel
			state.LoadResolver = append(state.LoadResolver, scanner.Text())
		}
	}

	// Use the default resolvers
	if state.ComResolver == "" && state.ListResolver == "" {
		state.LoadResolver = append(state.LoadResolver, "1.1.1.1")
		state.LoadResolver = append(state.LoadResolver, "8.8.8.8")
		state.LoadResolver = append(state.LoadResolver, "8.8.4.4")
	}

	if state.Output != "" {
		dir := filepath.Dir(state.Output)
		exists, _ := helper.Exists(dir)
		if exists == false {
			fmt.Printf("\n%s-> The specified output directory does not exists !%s\n", helper.Yellow, helper.Reset)
		} else {
			// Get a handle to the out file if it is not json
			if state.AquatoneJSON != true && state.IsJSON != true {
				state.OutputHandle, err = os.OpenFile(state.Output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
				if err != nil {
					return
				}

			}
		}
	} else if state.OutputDir != "" {
		exists, _ := helper.Exists(state.OutputDir)
		if exists == false {
			fmt.Printf("\n%s-> The specified output directory does not exists !%s\n", helper.Yellow, helper.Reset)
		}
	}

	if state.Domain == "" && state.DomainList == "" {
		if state.Silent != true {
			fmt.Printf("\n\n%s-> Missing \"domain\" argument %s\nTry %s'./subfinder -h'%s for more information\n", helper.Bad, helper.Reset, helper.Info, helper.Reset)
		}
		os.Exit(1)
	}

	_ = passive.Enumerate(state)
	fmt.Printf("\n")
	//bruteforce.Bruteforce(state)
}
