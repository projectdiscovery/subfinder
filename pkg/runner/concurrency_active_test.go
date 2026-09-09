package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

func activeTestResolver(t *testing.T, handler dns.HandlerFunc) *resolve.Resolver {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	options := dnsx.DefaultOptions
	options.BaseResolvers = []string{conn.LocalAddr().String()}
	options.MaxRetries = 1
	options.Hostsfile = false
	options.Timeout = 100 * time.Millisecond
	client, err := dnsx.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return &resolve.Resolver{DNSClient: client}
}

func TestEnumerateMultipleDomainsActive(t *testing.T) {
	source := &delayedSource{delay: 15 * time.Millisecond}
	r := delayedRunner(t, 4, source)
	r.options.RemoveWildcard = true
	r.options.HostIP = true
	var active, peak, probes, hosts atomic.Int32
	r.resolverClient = activeTestResolver(t, func(w dns.ResponseWriter, request *dns.Msg) {
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		ip := "192.0.2.2"
		if strings.HasPrefix(request.Question[0].Name, "www.") {
			ip = "192.0.2.1"
			if request.Question[0].Qtype == dns.TypeA {
				hosts.Add(1)
			}
		} else {
			if request.Question[0].Qtype == dns.TypeA {
				probes.Add(1)
			}
		}
		answer, _ := dns.NewRR(request.Question[0].Name + " 60 IN A " + ip)
		response := new(dns.Msg)
		response.SetReply(request)
		if request.Question[0].Qtype == dns.TypeA {
			response.Answer = []dns.RR{answer}
		}
		active.Add(-1)
		_ = w.WriteMsg(response)
	})
	var callbacks []string
	r.options.ResultCallback = func(entry *resolve.HostEntry) { callbacks = append(callbacks, entry.Host) }
	var input, output strings.Builder
	for i := range 12 {
		fmt.Fprintf(&input, "target-%d.example\n", i)
	}
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(input.String()), []io.Writer{&output}); err != nil {
		t.Fatal(err)
	}
	if got := source.peak.Load(); got < 2 || got > 4 {
		t.Fatalf("concurrent domains=%d, want 2..4", got)
	}
	if got := peak.Load(); got < 2 || got > 4 {
		t.Fatalf("concurrent DNS calls=%d, want 2..4", got)
	}
	if probes.Load() != 36 || hosts.Load() != 12 {
		t.Fatalf("probes=%d hosts=%d, want 36 and 12", probes.Load(), hosts.Load())
	}
	if len(callbacks) != 12 {
		t.Fatalf("callbacks=%d, want 12", len(callbacks))
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 12 {
		t.Fatalf("output lines=%d, want 12", len(lines))
	}
	for i := range 12 {
		want := fmt.Sprintf("www.target-%d.example,192.0.2.1,benchmark-delay", i)
		if !strings.Contains(output.String(), want+"\n") {
			t.Errorf("missing output %q in %q", want, output.String())
		}
	}
}

func TestEnumerateMultipleDomainsActiveCancellation(t *testing.T) {
	source := &delayedSource{delay: time.Millisecond}
	r := delayedRunner(t, 4, source)
	r.options.RemoveWildcard = true
	r.options.HostIP = true
	started := make(chan struct{}, 4)
	r.resolverClient = activeTestResolver(t, func(_ dns.ResponseWriter, _ *dns.Msg) {
		select {
		case started <- struct{}{}:
		default:
		}
		// No response: the active DNSX call must finish through its own timeout.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- r.EnumerateMultipleDomainsWithCtx(ctx, strings.NewReader(strings.Repeat("target.example\n", 12)), nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DNS query did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active enumeration did not stop after DNS timeout")
	}
	if source.active.Load() != 0 {
		t.Fatal("source still active after cancellation")
	}
}
