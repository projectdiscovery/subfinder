package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// parseRateLimitString parses a rate limit string in the format "N/s" or "N/m" or just "N"
func parseRateLimitString(s string) (uint, time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "/m") {
		s = strings.TrimSuffix(s, "/m")
		n, err := parseInt(s)
		if err != nil {
			return 0, 0, err
		}
		return uint(n), time.Minute, nil
	}
	if strings.HasSuffix(s, "/s") {
		s = strings.TrimSuffix(s, "/s")
		n, err := parseInt(s)
		if err != nil {
			return 0, 0, err
		}
		return uint(n), time.Second, nil
	}
	// Also handle "2m" format (without slash) - from issue example "2/m"
	if strings.HasSuffix(s, "m") {
		s = strings.TrimSuffix(s, "m")
		n, err := parseInt(s)
		if err != nil {
			return 0, 0, err
		}
		return uint(n), time.Minute, nil
	}
	if strings.HasSuffix(s, "s") {
		s = strings.TrimSuffix(s, "s")
		n, err := parseInt(s)
		if err != nil {
			return 0, 0, err
		}
		return uint(n), time.Second, nil
	}
	n, err := parseInt(s)
	if err != nil {
		return 0, 0, err
	}
	return uint(n), time.Second, nil
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
