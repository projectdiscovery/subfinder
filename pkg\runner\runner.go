package runner

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options          *Options
	passiveAgent     *passive.Agent
	resolverClient   *resolve.Resolver
	rateLimiter      *ratelimit.Limiter
	multiRateLimiter *ratelimit.MultiLimiter
}
