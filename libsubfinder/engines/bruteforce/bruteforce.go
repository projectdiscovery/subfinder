//
// bruteforce.go : A DNS Bruteforcer in Golang
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
// All Rights Reserved

package bruteforce

import (
	"fmt"

	"github.com/Ice3man543/subfinder/libsubfinder/helper"
)

func consume(args ...interface{}) interface{} {
	target := args[0].(string)
	state := args[1].(*helper.State)
	domain := args[2].(string)
	ips, err := helper.ResolveHost(fmt.Sprintf("%s.%s", target, domain))
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
func Brute(state *helper.State, list []string, domain string) (subdomains []helper.Domain) {

	brutePool := helper.NewPool(state.Threads)

	brutePool.Run()

	// add jobs
	for _, target := range list {
		// Send the job to the channel
		brutePool.Add(consume, target, state, domain)
	}

	brutePool.Wait()

	var ValidSubdomains []helper.Domain

	completedJobs := brutePool.Results()
	for _, job := range completedJobs {
		if job.Result != "" {
			fqdn := job.Args[0].(string)
			ip := job.Result.(string)
			subdomain := helper.Domain{IP: ip, Fqdn: fmt.Sprintf("%s.%s", fqdn, domain)}
			if state.Silent != true {
				if state.Verbose == true {
					fmt.Printf("\n[%sBRUTE%s] %s : %s", helper.Info, helper.Reset, subdomain.Fqdn, subdomain.IP)
				}
			}
			ValidSubdomains = append(ValidSubdomains, subdomain)
		}
	}

	brutePool.Stop()

	return ValidSubdomains
}
