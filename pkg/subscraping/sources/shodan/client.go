package shodan

import (
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

// Client is the Shodan API client
type Client struct {
	apiURL  string
	apiKey  string
	ctx     context.Context
	session *subscraping.Session
}

// SSLLookUpResponse is the response type for domain certificates search
type SSLLookUpResponse struct {
	Matches []struct {
		Hostnames []string `json:"hostnames"`
	} `json:"matches"`
	Result int    `json:"result"`
	Error  string `json:"error"`
}

// DNSDBLookupResponse is the response type for Shodan's main domain discovery API
type DNSDBLookupResponse struct {
	Domain string `json:"domain"`
	Data   []struct {
		Subdomain string `json:"subdomain"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"data"`
	Result int    `json:"result"`
	Error  string `json:"error"`
}

// NewClient initializes the Shodan API client
func NewClient(ctx context.Context, apiURL, apiKey string, session *subscraping.Session) *Client {
	return &Client{
		apiURL:  apiURL,
		apiKey:  apiKey,
		ctx:     ctx,
		session: session,
	}
}

// DNSDBLookup call Shodan's main domain discovery API
func (client *Client) DNSDBLookup(domain string) (DNSDBLookupResponse, error) {
	searchURL := fmt.Sprintf("%s/dns/domain/%s?key=%s", client.apiURL, domain, client.apiKey)

	var response DNSDBLookupResponse

	err := request(searchURL, &response, client)
	if err != nil {
		return response, err
	}

	if response.Error != "" {
		return response, fmt.Errorf("%v", response.Error)
	}

	return response, nil
}

// SSLLookupQuery queries Shodan's API for domain certificates
func (client *Client) SSLLookupQuery(domain string) (SSLLookUpResponse, error) {
	var response SSLLookUpResponse

	err := query(domain, "ssl.cert.subject.cn", &response, client)
	if err != nil {
		return response, err
	}

	if response.Error != "" {
		return response, fmt.Errorf("%v", response.Error)
	}

	return response, nil
}

// query can do generic queries to Shodan's API search
func query(domain, query string, response interface{}, client *Client) error {
	searchURL := fmt.Sprintf(
		"%s/shodan/host/search?query=%s:%s&key=%s",
		client.apiURL,
		query,
		domain,
		client.apiKey,
	)

	err := request(searchURL, response, client)
	if err != nil {
		return err
	}

	return nil
}

// request can do a generic HTTP request to Shodan's API
func request(searchURL string, response interface{}, client *Client) error {
	resp, err := client.session.SimpleGet(client.ctx, searchURL)
	if err != nil {
		client.session.DiscardHTTPResponse(resp)
		return err
	}

	defer resp.Body.Close()

	err = jsoniter.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return err
	}

	return nil
}
