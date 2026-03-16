package subscraping

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/gologger"
)

// NewSession creates a new session object for a domain
func NewSession(domain string, proxy string, multiRateLimiter *ratelimit.MultiLimiter, timeout int) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: (&net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}).Dial,
	}

	// Add proxy
	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		if proxyURL == nil {
			// Log warning but continue anyway
			gologger.Warning().Msgf("Invalid proxy provided: %s", proxy)
		} else {
			Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	session := &Session{Client: client, Timeout: timeout}

	// Initiate rate limit instance
	session.MultiRateLimiter = multiRateLimiter

	// Create a new extractor object for the current domain
	extractor, err := NewSubdomainExtractor(domain)
	session.Extractor = extractor

	return session, err
}

// Get makes a GET request to a URL with extended parameters
func (s *Session) Get(ctx context.Context, getURL, cookies string, headers map[string]string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, cookies, headers, nil, BasicAuth{})
}

// SimpleGet makes a simple GET request to a URL
func (s *Session) SimpleGet(ctx context.Context, getURL string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, "", map[string]string{}, nil, BasicAuth{})
}

// Post makes a POST request to a URL with extended parameters
func (s *Session) Post(ctx context.Context, postURL, cookies string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, cookies, headers, body, BasicAuth{})
}

// SimplePost makes a simple POST request to a URL
func (s *Session) SimplePost(ctx context.Context, postURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, "", map[string]string{"Content-Type": contentType}, body, BasicAuth{})
}

// HTTPRequest makes any HTTP request to a URL with extended parameters
func (s *Session) HTTPRequest(ctx context.Context, method, requestURL, cookies string, headers map[string]string, body io.Reader, basicAuth BasicAuth) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Connection", "close")

	if basicAuth.Username != "" || basicAuth.Password != "" {
		req.SetBasicAuth(basicAuth.Username, basicAuth.Password)
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	sourceName := ctx.Value(CtxSourceArg).(string)
	mrlErr := s.MultiRateLimiter.Take(sourceName)
	if mrlErr != nil {
		return nil, mrlErr
	}

	return httpRequestWrapper(s.Client, req)
}

// DiscardHTTPResponse discards the response content by demand
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response != nil {
		_, err := io.Copy(io.Discard, response.Body)
		if err != nil {
			gologger.Warning().Msgf("Could not discard response body: %s\n", err)
			return
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			gologger.Warning().Msgf("Could not close response body: %s\n", closeErr)
		}
	}
}

// Close the session
func (s *Session) Close() {
	s.MultiRateLimiter.Stop()
	s.Client.CloseIdleConnections()
}

func httpRequestWrapper(client *http.Client, request *http.Request) (*http.Response, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())

		gologger.Debug().MsgFunc(func() string {
			buffer := new(bytes.Buffer)
			_, _ = buffer.ReadFrom(response.Body)
			return fmt.Sprintf("Response for failed request against %s:\n%s", requestURL, buffer.String())
		})
		return response, fmt.Errorf("unexpected status code %d received from %s", response.StatusCode, requestURL)
	}
	return response, nil
}
