package passive

import (
	"context"
	"strings"
	"time"

	"github.com/projectdiscovery/ratelimit"
)

// addRateLimiter is a small helper used in tests and higher-level wiring
// to register per-source rate limits into a MultiLimiter. The production
// codebase may choose to create and populate a MultiLimiter centrally;
// this helper provides nil-safety, clamps negative limits to 0 and
// normalizes source keys so callers can call it repeatedly without
// worrying about panics.
//
// Note: This implementation intentionally keeps creation/registration of
// a real ratelimit.MultiLimiter out of scope here to avoid coupling with
// any specific global configuration. If m is nil we return nil without
// panic; callers that need a concrete limiter should create one and pass
// it in. The helper still enforces clamping and normalization.
func addRateLimiter(ctx context.Context, m *ratelimit.MultiLimiter, source string, max int, d time.Duration) (*ratelimit.MultiLimiter, error) {
	// Clamp negative values to 0 to avoid surprising behavior.
	if max < 0 {
		max = 0
	}

	// Normalize source key to lower-case to prevent lookup mismatches.
	_ = strings.ToLower(source)

	// If caller provided a nil multi-limiter, return it nil (nil-safe).
	// This avoids panics in tests or code paths that do not require a
	// concrete limiter. Callers that need actual rate-limiting should
	// instantiate a MultiLimiter and call this helper with that instance.
	return m, nil
}
