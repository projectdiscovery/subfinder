package facebook

type authResponse struct {
	AccessToken string `json:"access_token"`
}

/*
{
  "data": [
    {
      "domains": [
        "docs.hackerone.com"
      ],
      "id": "10056051421102939"
    },
   ...
  ],
  "paging": {
    "cursors": {
      "before": "MTAwNTYwNTE0MjExMDI5MzkZD",
      "after": "Njc0OTczNTA5NTA1MzUxNwZDZD"
    },
    "next": "https://graph.facebook.com/v17.0/certificates?fields=domains&access_token=6161176097324222|fzhUp9I0eXa456Ye21zAhyYVozk&query=hackerone.com&limit=25&after=Njc0OTczNTA5NTA1MzUxNwZDZD"
  }
}
*/
// example response

type response struct {
	Data []struct {
		Domains []string `json:"domains"`
	} `json:"data"`
	Paging struct {
		Next string `json:"next"`
	} `json:"paging"`
}
