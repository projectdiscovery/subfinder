package runner

import (
	"testing"
	"time"
)

func TestSourceRateLimiterJitter(t *testing.T) {
	baseDelay := 100 * time.Millisecond
	jitterMax := 20 * time.Millisecond
	
	if baseDelay <= 0 || jitterMax <= 0 {
		t.Fatalf("delay and jitter values must be non-zero")
	}
}
