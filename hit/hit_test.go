package hit

import (
	"net/http/httptest"
	"testing"
)

func TestRedactQuery(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"q=hello&page=2", "q=hello&page=2"},
		{"api_key=abc123&maxWidth=300", "api_key=REDACTED&maxWidth=300"},
		{"Tag=x&ApiKey=abc&X-Emby-Token=def", "Tag=x&ApiKey=REDACTED&X-Emby-Token=REDACTED"},
		{"token=", "token=REDACTED"},
		{"api_key", "api_key"}, // no value, nothing to hide
	} {
		if got := RedactQuery(tc.in); got != tc.want {
			t.Errorf("RedactQuery(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeRedacts(t *testing.T) {
	h := Hit{
		Query:   "api_key=secret&format=webp",
		Referer: "https://jellyfin.example.com/web/?api_key=secret#/home",
	}
	h.Sanitize()
	if h.Query != "api_key=REDACTED&format=webp" {
		t.Errorf("query = %q", h.Query)
	}
	if h.Referer != "https://jellyfin.example.com/web/?api_key=REDACTED#/home" {
		t.Errorf("referer = %q", h.Referer)
	}
}

func TestClientIP(t *testing.T) {
	trusted, _ := ParsePrefixes("127.0.0.1/32,192.168.0.0/16")
	for _, tc := range []struct {
		name, peer, xff, want string
	}{
		{"untrusted peer ignores xff", "203.0.113.9:1", "1.2.3.4", "203.0.113.9"},
		{"proxy, public client", "127.0.0.1:1", "198.51.100.7", "198.51.100.7"},
		{"spoofed left hop ignored", "127.0.0.1:1", "6.6.6.6, 198.51.100.7", "198.51.100.7"},
		{"all hops trusted: leftmost", "192.168.1.2:1", "192.168.1.50, 192.168.1.3", "192.168.1.50"},
		{"garbage untrusted hop: peer", "127.0.0.1:1", "not-an-ip", "127.0.0.1"},
		{"no xff: peer", "127.0.0.1:1", "", "127.0.0.1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.peer
		if tc.xff != "" {
			r.Header.Set("X-Forwarded-For", tc.xff)
		}
		if got, _ := ClientIP(r, trusted); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}
