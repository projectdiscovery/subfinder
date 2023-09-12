package facebook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/generic"
)

var (
	fb_API_ID     = "$FB_APP_ID"
	fb_API_SECRET = "$FB_APP_SECRET"
)

func TestFacebookSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	updateWithEnv(&fb_API_ID)
	updateWithEnv(&fb_API_SECRET)
	if generic.EqualsAny("", fb_API_ID, fb_API_SECRET) {
		t.SkipNow()
	}
	k := apiKey{
		AppID:  fb_API_ID,
		Secret: fb_API_SECRET,
	}
	k.FetchAccessToken()
	if k.Error != nil {
		t.Fatal(k.Error)
	}

	fetchURL := fmt.Sprintf("https://graph.facebook.com/certificates?fields=domains&access_token=%s&query=hackerone.com&limit=5", k.AccessToken)
	resp, err := retryablehttp.Get(fetchURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	response := &response{}
	if err := json.Unmarshal(bin, response); err != nil {
		t.Fatal(err)
	}
	if len(response.Data) == 0 {
		t.Fatal("no data found")
	}
}

func updateWithEnv(key *string) {
	if key == nil {
		return
	}
	value := *key
	if strings.HasPrefix(value, "$") {
		*key = os.Getenv(value[1:])
	}
}
