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
    "sync"

    "github.com/Ice3man543/subfinder/libsubfinder/helper"
)

var ValidSubdomains []*helper.Job
var wg, wg2 sync.WaitGroup

func analyze(state *helper.State, results <-chan *helper.Job) {
    defer wg2.Done()
    for job := range results {
        if job.Result != "" {
            if state.Silent != true {
                if state.Verbose == true {
                    fmt.Printf("\n[RESOLVED] %s : %s", job.Work, job.Result)
                }
            }
            ValidSubdomains = append(ValidSubdomains, job)
        }
    }
}

func consume(jobs <-chan *helper.Job, results chan<- *helper.Job, state *helper.State) {
    defer wg.Done()
    for job := range jobs {
        ips, err := helper.ResolveHost(job.Work)
        if err != nil {
            continue
        }

        if len(ips) <= 0 {
            // We didn't found any ips
            job.Result = ""
            results <- job
        } else {
            if state.IsWildcard == true {
                result := helper.CheckWildcard(state, ips)
                if result == true {
                    // We have a wildcard ip
                    job.Result = ""
                    results <- job
                } else {
                    // Not a wildcard subdomains ip
                    job.Result = ips[0]
                    results <- job
                }
            } else {
                job.Result = ips[0]
                results <- job
            }
        }
    }
}

func produce(jobs chan<- *helper.Job, list []string) {

    for _, target := range list {
        // Send the job to the channel
        jobs <- &helper.Job{Work: fmt.Sprintf("%s", target), Result: ""}
    }

    close(jobs)
}

func Resolve(state *helper.State, list []string) (subdomains []*helper.Job) {
    jobs := make(chan *helper.Job, 100)    // Buffered channel
    results := make(chan *helper.Job, 100) // Buffered channel

    // Start consumers:
    for i := 0; i < state.Threads; i++ {
        wg.Add(1)
        go consume(jobs, results, state)
    }

    // Start producing
    go produce(jobs, list)

    // Start analyzing
    wg2.Add(1)
    go analyze(state, results)

    wg.Wait()
    close(results)

    wg2.Wait()

    return ValidSubdomains
}
