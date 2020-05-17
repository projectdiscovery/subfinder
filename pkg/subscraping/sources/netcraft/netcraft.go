// Package netcraft is a NetCraft Scraping Engine in Golang
package netcraft

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"

	"github.com/projectdiscovery/subfinder/pkg/subscraping"
)

var name = "netcraft"
var reNext = regexp.MustCompile("href=\"(.*host=.*?&.*last=.*?&.*from=.*?)&.*\"")
var netcraft_url = "https://searchdns.netcraft.com"

type Agent struct {
	Results chan subscraping.Result
	Session *subscraping.Session
}

func SHA1(text string) string {
	decodedValue, err := url.QueryUnescape(text)
	if err != nil {
		return ""
	}
	algorithm := sha1.New()
	algorithm.Write([]byte(decodedValue))
	return string(fmt.Sprintf("%x", algorithm.Sum(nil)))
}

func (a *Agent) getJsCookies(ctx context.Context, baseURL string) (string, error) {
	cookie_value := ""
	resp, err := a.Session.NormalGetWithContext(ctx, baseURL)

	if err != nil {
		return cookie_value, err
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "netcraft_js_verification_challenge" {
			cookie_value = cookie.Name + "=" + cookie.Value + "; netcraft_js_verification_response=" + SHA1(cookie.Value)
			break
		}
	}
	return cookie_value, err
}

func (a *Agent) enumerate(ctx context.Context, baseURL string, cookies string, headers map[string]string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.Session.Get(ctx, baseURL, cookies, headers)
	if err != nil {
		a.Results <- subscraping.Result{Source: name, Type: subscraping.Error, Error: err}
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		a.Results <- subscraping.Result{Source: name, Type: subscraping.Error, Error: err}
		return
	}

	src := string(body)

	for _, subdomain := range a.Session.Extractor.FindAllString(src, -1) {
		a.Results <- subscraping.Result{Source: name, Type: subscraping.Subdomain, Value: subdomain}
	}

	match1 := reNext.FindStringSubmatch(src)
	if len(match1) > 0 {
		a.enumerate(ctx, netcraft_url+match1[1], cookies, headers)
	}
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)

	aInstance := Agent{
		Session: session,
		Results: results,
	}

	go func() {
		cookies, err := aInstance.getJsCookies(ctx, netcraft_url)
		if err != nil {
			aInstance.Results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			return
		}
		aInstance.enumerate(ctx, netcraft_url+"/?host="+domain, cookies, map[string]string{"Host": "searchdns.netcraft.com"})
		close(aInstance.Results)
	}()

	return aInstance.Results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return name
}
