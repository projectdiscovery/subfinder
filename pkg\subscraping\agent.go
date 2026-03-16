package subscraping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"golang.org/x/exp/maps"
)

// Agent is a struct for interacting with a source
type Agent struct {
	RateLimiter      *ratelimit.Limiter
	MultiRateLimiter *ratelimit.MultiLimiter
}

// NewAgent creates a new agent with the given rate limiters
func NewAgent(rateLimiter *ratelimit.Limiter, multiRateLimiter *ratelimit.MultiLimiter) *Agent {
	return &Agent{
		RateLimiter:      rateLimiter,
		MultiRateLimiter: multiRateLimiter,
	}
}

// GetRateLimiter returns the appropriate rate limiter for a given source
func (a *Agent) GetRateLimiter(source string) *ratelimit.Limiter {
	if a.MultiRateLimiter != nil {
		if limiter, err := a.MultiRateLimiter.GetLimiter(source); err == nil {
			return limiter
		}
	}
	return a.RateLimiter
}
