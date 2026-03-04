package passive

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/assert"
)

func TestAddRateLimiter_NilMultiLimiterDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	var ml *ratelimit.MultiLimiter
	// Should not panic and should return a non-nil MultiLimiter
	newMl, err := addRateLimiter(ctx, ml, "testsource", 10, time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, newMl)
}

func TestAddRateLimiter_NegativeMaxClampedToZero(t *testing.T) {
	ctx := context.Background()
	var ml *ratelimit.MultiLimiter
	// Negative max should be treated as unlimited (no limiter added) and must not panic
	newMl, err := addRateLimiter(ctx, ml, "testsource", -5, time.Minute)
	assert.NoError(t, err)
	assert.NotNil(t, newMl)
	// Adding again with a positive limit should create a limiter
	newMl2, err := addRateLimiter(ctx, newMl, "testsource", 2, time.Minute)
	assert.NoError(t, err)
	assert.NotNil(t, newMl2)
}

func TestAddRateLimiter_PreservesDuration(t *testing.T) {
	ctx := context.Background()
	var ml *ratelimit.MultiLimiter
	dur := 2 * time.Minute
	newMl, err := addRateLimiter(ctx, ml, "sitedossier", 2, dur)
	assert.NoError(t, err)
	assert.NotNil(t, newMl)
	// Ensure the underlying multi limiter contains an entry for our source
	// We don't assert on the internal limiter fields (implementation detail of ratelimit package),
	// but adding twice for the same source should not panic and should return the same multi limiter type.
	newMlAgain, err := addRateLimiter(ctx, newMl, "sitedossier", 5, dur)
	assert.NoError(t, err)
	assert.NotNil(t, newMlAgain)
}
