//
// resolver.go : A Resolving package in golang
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
// All Rights Reserved

package resolver

import (
	"fmt"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

func consume(args ...interface{}) interface{} {
	target := args[0].(string)
	state := args[1].(*helper.State)
	ips, err := helper.ResolveHost(target)
	if err != nil {
		return ""
	}

	if len(ips) <= 0 {
		// We didn't found any ips
		return ""
	} else {
		if state.IsWildcard == true {
			result := helper.CheckWildcard(state, ips)
			if result == true {
				// We have a wildcard ip
				return ""
			}
			return ips[0]
		}
		return ips[0]
	}
}

// Resolve handle a list of subdomains to resolve
func Resolve(state *helper.State, list []string) (subdomains []string) {

	resolverPool := helper.NewPool(state.Threads)

	resolverPool.Run()

	// add jobs
	for _, target := range list {
		// Send the job to the channel
		resolverPool.Add(consume, target, state)
	}

	resolverPool.Wait()

	var ValidSubdomains []string

	completedJobs := resolverPool.Results()
	for _, job := range completedJobs {
		if job.Result != nil {
			result := job.Result.(string)
			if !state.Silent {
				target := job.Args[0].(string)
				fmt.Printf("\n[+] %s : %s", target, job.Result)
			}
			ValidSubdomains = append(ValidSubdomains, result)
		}
	}

	resolverPool.Stop()

	return ValidSubdomains
}
