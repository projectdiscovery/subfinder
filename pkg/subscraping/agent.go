package subscraping

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// NewSession creates a new session object for a domain
func NewSession(domain string, keys *Keys, timeout int) (*Session, error) {
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
func (s *Session) NormalGetWithContext(ctx context.Context, getURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", getURL, nil)
	if err != nil {
		return nil, err
	}

	// Don't randomize user agents, as they cause issues sometimes
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")

	return httpRequestWrapper(s.Client, req)
}

// Get makes a GET request to a URL
func (s *Session) Get(ctx context.Context, getURL string, cookies string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", getURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return httpRequestWrapper(s.Client, req)
}

// DiscardHTTPResponse discards the response content by demand
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response != nil {
		io.Copy(ioutil.Discard, response.Body)
		response.Body.Close()
	}
}

func httpRequestWrapper(client *http.Client, request *http.Request) (*http.Response, error) {
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())
		return resp, fmt.Errorf("unexpected status code %d received from %s", resp.StatusCode, requestURL)
	}
	return resp, nil
}
