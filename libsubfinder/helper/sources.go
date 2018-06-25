//
// helper.go : Main sources driver. Contains helper functions for other sources.
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package helper

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// GetHTTPResponse : Returns a HTTP Response object
// It needs URL To Visit. Note, It needs full url with scheme and a timeout value.
// It returns a HTTP Response object
func GetHTTPResponse(url string, timeout int) (resp *http.Response, err error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return resp, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1")
	req.Header.Add("Connection", "close")

	resp, err = client.Do(req)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// GetHTTPCookieResponse returns a HTTP Response object
// It needs URL To Visit and a cookie array to send with request.
// Note, It needs full url with scheme and a timeout value.
// It returns a HTTP Response object with a cookie array.
func GetHTTPCookieResponse(urls string, cookies []*http.Cookie, timeout int) (resp *http.Response, cookie []*http.Cookie, err error) {

	var curCookieJar *cookiejar.Jar

	curCookieJar, _ = cookiejar.New(nil)

	// Add the cookies received via request params
	u, _ := url.Parse(urls)
	curCookieJar.SetCookies(u, cookies)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Jar:       curCookieJar,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	req, err := http.NewRequest("GET", urls, nil)
	if err != nil {
		return resp, cookie, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1")
	req.Header.Add("Connection", "close")

	resp, err = client.Do(req)
	if err != nil {
		return resp, cookie, err
	}

	cookie = curCookieJar.Cookies(req.URL)

	return resp, cookie, nil
}
