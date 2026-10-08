package resolve

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

func TestSharedLimitBoundsWorkerGoroutines(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolver := New().WithConcurrencyLimit(16)
	before := runtime.NumGoroutine()
	var pools []*ResolutionPool
	for range 12 {
		pool := resolver.NewResolutionPoolWithCtx(ctx, 16, false)
		pools = append(pools, pool)
		pool.Tasks <- HostEntry{Host: "example.com"}
	}
	// Results remain unread, so workers cannot finish while their count is checked.
	if added := runtime.NumGoroutine() - before; added > 48 {
		t.Errorf("added %d goroutines for 12 pools with a shared limit of 16", added)
	}
	cancel()
	for _, pool := range pools {
		close(pool.Tasks)
		for range pool.Results {
		}
	}
}

func TestBoundedPoolUsesAvailableWorkers(t *testing.T) {
	for _, limits := range [][2]int{{2, 4}, {4, 2}} {
		ctx, cancel := context.WithCancel(context.Background())
		resolver := New().WithConcurrencyLimit(limits[0])
		pool := resolver.NewResolutionPoolWithCtx(ctx, limits[1], false)
		// Receiving the third task requires the dispatcher to have started two
		// workers. Unread results hold their slots until cancellation below.
		for range 3 {
			pool.Tasks <- HostEntry{Host: "example.com"}
		}
		if got := len(resolver.lookupSlots); got != 2 {
			t.Errorf("global=%d pool=%d: occupied slots=%d, want 2", limits[0], limits[1], got)
		}
		cancel()
		close(pool.Tasks)
		for range pool.Results {
		}
	}
}

func TestCanceledLookupWait(t *testing.T) {
	original := New()
	bounded := original.WithConcurrencyLimit(1)
	if original.lookupSlots != nil || bounded.DNSClient != original.DNSClient {
		t.Fatal("bounded resolver must leave original unchanged and share DNS client")
	}
	bounded.lookupSlots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	pool := bounded.NewResolutionPoolWithCtx(ctx, 1, true)
	pool.Tasks <- HostEntry{Host: "example.com"}
	cancel()
	select {
	case _, ok := <-pool.Results:
		if ok {
			t.Fatal("unexpected result after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("queued lookup did not stop")
	}
	close(pool.Tasks)
	if err := pool.InitWildcards("example.com"); err != context.Canceled {
		t.Fatalf("wildcard cancellation: %v", err)
	}
}

func TestSharedLookupLimit(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var active, peak atomic.Int32
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		ip := "192.0.2.1"
		if strings.HasSuffix(req.Question[0].Name, ".second.test.") {
			ip = "192.0.2.2"
		}
		answer, _ := dns.NewRR(req.Question[0].Name + " 60 IN A " + ip)
		response := new(dns.Msg)
		response.SetReply(req)
		response.Answer = []dns.RR{answer}
		active.Add(-1)
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	options := dnsx.DefaultOptions
	options.BaseResolvers = []string{conn.LocalAddr().String()}
	options.MaxRetries = 1
	options.Hostsfile = false
	client, err := dnsx.New(options)
	if err != nil {
		t.Fatal(err)
	}
	resolver := (&Resolver{DNSClient: client}).WithConcurrencyLimit(2)
	pools := []*ResolutionPool{
		resolver.NewResolutionPool(4, true),
		resolver.NewResolutionPool(4, true),
	}
	done := make(chan error, 2)
	for i, domain := range []string{"first.test", "second.test"} {
		go func() { done <- pools[i].InitWildcards(domain) }()
	}
	for range pools {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if _, exists := pools[0].wildcardIPs["192.0.2.2"]; exists {
		t.Fatal("wildcard state crossed domains")
	}
	for _, pool := range pools {
		go func() {
			for range 8 {
				pool.Tasks <- HostEntry{Host: "www.other.test"}
			}
			close(pool.Tasks)
		}()
		go func() {
			for range pool.Results {
			}
			done <- nil
		}()
	}
	for range pools {
		<-done
	}
	if got := peak.Load(); got != 2 {
		t.Fatalf("maximum concurrent DNS calls = %d, want 2", got)
	}
}

func TestResolutionPoolPassthrough(t *testing.T) {
	pool := New().NewResolutionPool(2, false)
	go func() {
		pool.Tasks <- HostEntry{Host: "www.example.com", Source: "test"}
		close(pool.Tasks)
	}()
	var results []Result
	for result := range pool.Results {
		results = append(results, result)
	}
	if len(results) != 1 || results[0].Host != "www.example.com" || results[0].Source != "test" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestCancellationReleasesBlockedResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool := New().NewResolutionPoolWithCtx(ctx, 1, false)
	pool.Tasks <- HostEntry{Host: "www.example.com"}
	cancel()
	close(pool.Tasks)
	done := make(chan struct{})
	go func() {
		for range pool.Results {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled result send blocked pool shutdown")
	}
}
