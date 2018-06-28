//
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man

// Package resolver is a fast dns resolver
package resolver

import (
	"fmt"

	"github.com/subfinder/subfinder/libsubfinder/helper"
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
	}

	if state.IsWildcard {
		result := helper.CheckWildcard(state, ips)
		if result {
			// We have a wildcard ip
			return ""
		}
	}

	if !state.Silent {
		if state.Verbose {
			fmt.Printf("\n[%sRESOLVED%s] %s : %s", helper.Info, helper.Reset, target, ips[0])
		}
	}
	return ips[0]
}

// Resolve handle a list of subdomains to resolve
func Resolve(state *helper.State, list []string) (subdomains []helper.Domain) {

	resolverPool := helper.NewPool(state.Threads)

	resolverPool.Run()

	// add jobs
	for _, target := range list {
		// Send the job to the channel
		resolverPool.Add(consume, target, state)
	}

	resolverPool.Wait()

	var ValidSubdomains []helper.Domain

	completedJobs := resolverPool.Results()
	for _, job := range completedJobs {
		if job.Result != "" {
			fqdn := job.Args[0].(string)
			ip := job.Result.(string)
			subdomain := helper.Domain{IP: ip, Fqdn: fqdn}
			if !state.Silent {
				if state.Verbose {
					fmt.Printf("\n[%sRESOLVED%s] %s : %s", helper.Info, helper.Reset, subdomain.Fqdn, subdomain.IP)
				}
			}
			ValidSubdomains = append(ValidSubdomains, subdomain)
		}
	}

	resolverPool.Stop()

	return ValidSubdomains
}
