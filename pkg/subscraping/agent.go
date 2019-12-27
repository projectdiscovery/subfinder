package subscraping

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// NewSession creates a new session object for a domain
func NewSession(domain string, keys Keys, timeout int) (*Session, error) {
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}

	session := &Session{
		Client: client,
		Keys:   keys,
	}

	// Create a new extractor object for the current domain
	extractor, err := NewSubdomainExtractor(domain)
	session.Extractor = extractor

	return session, err
}

// NormalGetWithContext makes a normal GET request to a URL with context
func (s *Session) NormalGetWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Don't randomize user agents, as they cause issues sometimes
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return resp, fmt.Errorf("subscraping.NormalGetWithContext - %s returned status code %v", url, resp.StatusCode)
	}

	return resp, nil
}

// NormalGetWithRetriesWithContext makes a normal GET request to a URL, with the specified number of retries
func (s *Session) NormalGetWithRetriesWithContext(ctx context.Context, url string, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		resp, err = s.NormalGetWithContext(ctx, url)
		if err == nil {
			return resp, err
		}
	}
	return nil, err
}

// Get makes a GET request to a URL
func (s *Session) Get(ctx context.Context, url string, cookies string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	if headers != nil {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return resp, fmt.Errorf("subscraping.Get - %s returned status code %v", url, resp.StatusCode)
	}

	return resp, nil
}
