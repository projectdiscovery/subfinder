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
			if state.Silent != true {
				if state.Verbose == true {
					fmt.Printf("\n[%sRESOLVED%s] %s : %s", helper.Info, helper.Reset, subdomain.Fqdn, subdomain.IP)
				}
			}
			ValidSubdomains = append(ValidSubdomains, subdomain)
		}
	}

	resolverPool.Stop()

	return ValidSubdomains
}
