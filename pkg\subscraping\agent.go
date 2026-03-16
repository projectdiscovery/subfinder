package subscraping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Agent is a struct for running passive subdomain enumeration
// against a given host. It keeps state about the source, performs
// requests and handles extraction of results.
type Agent struct {
	RateLimiter      *ratelimit.Limiter
	MultiRateLimiter *ratelimit.MultiLimiter
}

// NewAgent creates a new agent with rate limiters
func NewAgent(rateLimiter *ratelimit.Limiter, multiRateLimiter *ratelimit.MultiLimiter) *Agent {
	return &Agent{
		RateLimiter:      rateLimiter,
		MultiRateLimiter: multiRateLimiter,
	}
}

// CreateHttpClient creates an HTTP client for a given timeout and proxy
func (agent *Agent) CreateHttpClient(timeout int, proxy string) (*retryablehttp.Client, error) {
	retryablehttpOptions := retryablehttp.DefaultOptionsSpraying
	retryablehttpOptions.Timeout = time.Duration(timeout) * time.Second
	retryablehttpOptions.RetryMax = 2

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := retryablehttp.NewWithHTTPClient(&http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}, retryablehttpOptions)
	client.CheckRetry = retryablehttp.HostSprayingRetryPolicy()

	return client, nil
}

// Get makes a GET request to a URL and returns the response
func (agent *Agent) Get(ctx context.Context, source, url string, cookies string, headers map[string]string, body string) (*http.Response, error) {
	// Apply rate limiting
	if err := agent.RateLimit(ctx, source); err != nil {
		return nil, err
	}

	// Make the request
	// ...
	return nil, nil
}

// RateLimit applies rate limiting for a given source
func (agent *Agent) RateLimit(ctx context.Context, source string) error {
	if agent.MultiRateLimiter != nil {
		if err := agent.MultiRateLimiter.Take(source); err == nil {
			return nil
		}
	}
	if agent.RateLimiter != nil {
		agent.RateLimiter.Take()
	}
	return nil
}

// RequestWithCookieJar makes a request using cookie jar
func (agent *Agent) RequestWithCookieJar(ctx context.Context, source, url string, cookies string, headers map[string]string, body string, method string) (*http.Response, error) {
	if err := agent.RateLimit(ctx, source); err != nil {
		return nil, err
	}
	// ...
	return nil, nil
}
