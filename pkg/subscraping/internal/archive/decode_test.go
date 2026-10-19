package archive

import "testing"

func TestDecodeLine(t *testing.T) {
	cases := []struct{ input, want string }{
		{"https://2fa.example.com/", "https://2fa.example.com/"},
		{"%252F2fa.example.com/%25", "/2fa.example.com/   "},
		{"https://a.example.com/path%25", "https://a.example.com/path   "},
		{"%61.example.com", "a.example.com"},
		{"%2561.example.com", "a.example.com"},
		{"%252561.example.com", "a.example.com"},
		{"a+b%2Bc", "a b c"},
		{"%GGa.example.com/https://b.example.com", "                   /https://b.example.com"},
	}
	for _, tc := range cases {
		if got := DecodeLine(tc.input); got != tc.want {
			t.Errorf("DecodeLine(%q)=%q, want %q", tc.input, got, tc.want)
		}
	}
}
