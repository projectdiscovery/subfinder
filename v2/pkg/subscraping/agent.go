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

	"github.com/projectdiscovery/gologger"
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

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36")
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

	return httpRequestWrapper(s.Client, req)
}

// DiscardHTTPResponse discards the response content by demand
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response != nil {
		_, err := io.Copy(ioutil.Discard, response.Body)
		if err != nil {
			gologger.Warning().Msgf("Could not discard response body: %s\n", err)
			return
		}
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
