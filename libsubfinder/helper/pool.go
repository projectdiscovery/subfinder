//
// pool.go : contains pool helper function
// heavily based on: github.com/stefantalpalaru/pool
//

package helper

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"
)

// Job holds all the data related to a worker's instance.
type Job struct {
	F      func(...interface{}) interface{}
	Args   []interface{}
	Result interface{}
	Err    error
	added  chan bool // used by Pool.Add to wait for the supervisor
}

// Stats is a structure holding statistical data about the pool.
type Stats struct {
	Submitted int
	Running   int
	Completed int
}

// Pool is the main data structure.
type Pool struct {
	workersStarted     bool
	supervisorStarted  bool
	numWorkers         int
	jobWantedPipe      chan chan *Job
	donePipe           chan *Job
	addPipe            chan *Job
	resultWantedPipe   chan chan *Job
	jobsReadyToRun     *list.List
	numJobsSubmitted   int
	numJobsRunning     int
	numJobsCompleted   int
	jobsCompleted      *list.List
	interval           time.Duration // for sleeping, in ms
	workingWantedPipe  chan chan bool
	statsWantedPipe    chan chan Stats
	workerKillPipe     chan bool
	supervisorKillPipe chan bool
	workerWg           sync.WaitGroup
	supervisorWg       sync.WaitGroup
}

// subworker catches any panic while running the job.
func (pool *Pool) subworker(job *Job) {
	defer func() {
		if err := recover(); err != nil {
			log.Println("panic while running job:", err)
			job.Result = nil
			job.Err = fmt.Errorf(err.(string))
		}
	}()
	job.Result = job.F(job.Args...)
}

// worker gets a job from the job_pipe, passes it to a
// subworker and puts the job in the done_pipe when finished.
func (pool *Pool) worker(num int) {
	jobPipe := make(chan *Job)
WORKER_LOOP:
	for {
		pool.jobWantedPipe <- jobPipe
		job := <-jobPipe
		if job == nil {
			time.Sleep(pool.interval * time.Millisecond)
		} else {
			pool.subworker(job)
			pool.donePipe <- job
		}
		select {
		case <-pool.workerKillPipe:
			break WORKER_LOOP
		default:
		}
	}
	pool.workerWg.Done()
}

// NewPool creates a new Pool
func NewPool(workers int) (pool *Pool) {
	pool = new(Pool)
	pool.numWorkers = workers
	pool.jobWantedPipe = make(chan chan *Job)
	pool.donePipe = make(chan *Job)
	pool.addPipe = make(chan *Job)
	pool.resultWantedPipe = make(chan chan *Job)
	pool.jobsReadyToRun = list.New()
	pool.jobsCompleted = list.New()
	pool.workingWantedPipe = make(chan chan bool)
	pool.statsWantedPipe = make(chan chan Stats)
	pool.workerKillPipe = make(chan bool)
	pool.supervisorKillPipe = make(chan bool)
	pool.interval = 1
	// start the supervisor here so we can accept jobs before a Run call
	pool.startSupervisor()
	return
}

// supervisor feeds jobs to workers and keeps track of them.
func (pool *Pool) supervisor() {
SUPERVISOR_LOOP:
	for {
		select {
		// new job
		case job := <-pool.addPipe:
			pool.jobsReadyToRun.PushBack(job)
			pool.numJobsSubmitted++
			job.added <- true
		// send jobs to the workers
		case jobPipe := <-pool.jobWantedPipe:
			element := pool.jobsReadyToRun.Front()
			var job *Job
			if element != nil {
				job = element.Value.(*Job)
				pool.numJobsRunning++
				pool.jobsReadyToRun.Remove(element)
			}
			jobPipe <- job
		// job completed
		case job := <-pool.donePipe:
			pool.numJobsRunning--
			pool.jobsCompleted.PushBack(job)
			pool.numJobsCompleted++
		// wait for job
		case resultPipe := <-pool.resultWantedPipe:
			closePipe := false
			job := (*Job)(nil)
			element := pool.jobsCompleted.Front()
			if element != nil {
				job = element.Value.(*Job)
				pool.jobsCompleted.Remove(element)
			} else {
				if pool.numJobsRunning == 0 && pool.numJobsCompleted == pool.numJobsSubmitted {
					closePipe = true
				}
			}
			if closePipe {
				close(resultPipe)
			} else {
				resultPipe <- job
			}
		// is the pool working or just lazing on a Sunday afternoon?
		case workingPipe := <-pool.workingWantedPipe:
			working := true
			if pool.jobsReadyToRun.Len() == 0 && pool.numJobsRunning == 0 {
				working = false
			}
			workingPipe <- working
		// stats
		case statsPipe := <-pool.statsWantedPipe:
			poolStats := Stats{pool.numJobsSubmitted, pool.numJobsRunning, pool.numJobsCompleted}
			statsPipe <- poolStats
		// stopping
		case <-pool.supervisorKillPipe:
			break SUPERVISOR_LOOP
		}
	}
	pool.supervisorWg.Done()
}

// Run starts the Pool by launching the workers.
// It's OK to start an empty Pool. The jobs will be fed to the workers as soon
// as they become available.
func (pool *Pool) Run() {
	if pool.workersStarted {
		panic("trying to start a pool that's already running")
	}
	for i := 0; i < pool.numWorkers; i++ {
		pool.workerWg.Add(1)
		go pool.worker(i)
	}
	pool.workersStarted = true
	// handle the supervisor
	if !pool.supervisorStarted {
		pool.startSupervisor()
	}
}

// Stop will signal the workers to exit and wait for them to actually do that.
// It also releases any other resources (e.g.: it stops the supervisor goroutine)
// so call this method when you're done with the Pool instance to allow the GC
// to do its job.
func (pool *Pool) Stop() {
	if !pool.workersStarted {
		panic("trying to stop a pool that's already stopped")
	}
	// stop the workers
	for i := 0; i < pool.numWorkers; i++ {
		pool.workerKillPipe <- true
	}
	pool.workerWg.Wait()
	// set the flag
	pool.workersStarted = false
	// handle the supervisor
	if pool.supervisorStarted {
		pool.stopSupervisor()
	}
}

func (pool *Pool) startSupervisor() {
	pool.supervisorWg.Add(1)
	go pool.supervisor()
	pool.supervisorStarted = true
}

func (pool *Pool) stopSupervisor() {
	pool.supervisorKillPipe <- true
	pool.supervisorWg.Wait()
	pool.supervisorStarted = false
}

// Add creates a Job from the given function and args and
// adds it to the Pool.
func (pool *Pool) Add(f func(...interface{}) interface{}, args ...interface{}) {
	job := &Job{f, args, nil, nil, make(chan bool)}
	pool.addPipe <- job
	<-job.added
}

// Wait blocks until all the jobs in the Pool are done.
func (pool *Pool) Wait() {
	workingPipe := make(chan bool)
	for {
		pool.workingWantedPipe <- workingPipe
		if !<-workingPipe {
			break
		}
		time.Sleep(pool.interval * time.Millisecond)
	}
}

// Results retrieves the completed jobs.
func (pool *Pool) Results() (res []*Job) {
	res = make([]*Job, pool.jobsCompleted.Len())
	i := 0
	for e := pool.jobsCompleted.Front(); e != nil; e = e.Next() {
		res[i] = e.Value.(*Job)
		i++
	}
	pool.jobsCompleted = list.New()
	return
}

// WaitForJob blocks until a completed job is available and returns it.
// If there are no jobs running, it returns nil.
func (pool *Pool) WaitForJob() *Job {
	resultPipe := make(chan *Job)
	var job *Job
	var ok bool
	for {
		pool.resultWantedPipe <- resultPipe
		job, ok = <-resultPipe
		if !ok {
			// no more results available
			return nil
		}
		if job == (*Job)(nil) {
			// no result available right now but there are jobs running
			time.Sleep(pool.interval * time.Millisecond)
		} else {
			break
		}
	}
	return job
}

// Status returns a "stats" instance.
func (pool *Pool) Status() Stats {
	statsPipe := make(chan Stats)
	if pool.supervisorStarted {
		pool.statsWantedPipe <- statsPipe
		return <-statsPipe
	}
	// the supervisor wasn't started so we return a zeroed structure
	return Stats{}
}
