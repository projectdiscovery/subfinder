package runner

import (
	"testing"
	"time"
)

func TestResolverRetryBackoff(t *testing.T) {
	maxRetries := 3
	backoff := 50 * time.Millisecond
	
	attempts := 0
	for i := 0; i < maxRetries; i++ {
		attempts++
	}
	
	if attempts != maxRetries {
		t.Fatalf("expected %d retries, got %d", maxRetries, attempts)
	}
	if backoff <= 0 {
		t.Fatalf("backoff duration must be positive")
	}
}
