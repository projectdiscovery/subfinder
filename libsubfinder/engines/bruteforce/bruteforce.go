//
// brutefoce.go : Helper method for bruteforce functionality implemented
//	in subfinder.
//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package bruteforce

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"github.com/ice3man543/subfinder/libsubfinder/bruteforcer"
	"github.com/ice3man543/subfinder/libsubfinder/helper"
)

func Bruteforce(state *helper.State) (subdomains []string) {
	wildcard := helper.InitializeWildcardDNS(state)
	if wildcard == true {
		fmt.Printf("\n%s[!]%s Wildcard DNS Detected ! False Positives are likely :-(\n\n", helper.Cyan, helper.Reset)
	}

	subdomains, err := Process(state.Wordlist, state.Domain, state)
	if err != nil {
		fmt.Printf("\n%v\n", err)
		os.Exit(1)
	}

	return subdomains
}

func Process(wordlist string, domain string, state *helper.State) (subdomains []string, err error) {

	// Holds current words read from dictionary
	words := []string{}

	// Open the wordlist file
	wordfile, err := os.Open(state.Wordlist)
	if err != nil {
		return subdomains, err
	}

	scanner := bufio.NewScanner(wordfile)

	for scanner.Scan() {
		words = append(words, scanner.Text())
	}

	var wg sync.WaitGroup
	var channel = make(chan string)

	for i := 0; i < state.Threads; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			bruteforcer.CheckDNSEntry(state, domain, channel)
		}()
	}

	for _, word := range words {
		channel <- word
	}

	for _, _ = range words {
		result := <-channel
		if result != "" {
			fmt.Printf("%s\n", result)
		}
	}

	wg.Wait()

	return subdomains, err
}
