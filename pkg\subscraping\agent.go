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
// against a given host. It keeps state about the client, rate limiters,
// and handles HTTP requests.
type Agent struct {
	RateLimiter      *ratelimit.Limiter
	MultiRateLimiter *ratelimit.MultiLimiter
}

// NewAgent creates a new agent instance
func NewAgent(rateLimiter *ratelimit.Limiter, multiRateLimiter *ratelimit.MultiLimiter) *Agent {
	return &Agent{
		RateLimiter:      rateLimiter,
		MultiRateLimiter: multiRateLimiter,
	}
}
