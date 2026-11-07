package jellyfin

import (
	"errors"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
)

func TestParseLine(t *testing.T) {
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	const head = "2026-10-05T19:56:53-04:00 media-box jellyfin[9130]: [19:56:53] [INF] [93] "
	r, err := Jellyfin{}.ParseLine(head+"Jellyfin.Server.Implementations.Users.UserManager: Authentication request for admin has been denied (IP: ::ffff:203.0.113.9).", now)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Auth
	if a == nil || a.IP != "203.0.113.9" || a.User != "admin" || a.Source != "jellyfin" ||
		!a.TS.Equal(time.Date(2026, 10, 5, 23, 56, 53, 0, time.UTC)) {
		t.Errorf("got %+v", a)
	}
	for _, line := range []string{
		head + "Jellyfin.Server.Implementations.Users.UserManager: Authentication request for alice has succeeded.",
		head + "Jellyfin.Api.Auth.CustomAuthenticationHandler: CustomAuthentication was not authenticated. Failure message: Invalid token.",
		"2026-10-05T19:56:53-04:00 media-box sshd[1]: Authentication request for admin has been denied (IP: 203.0.113.9).",
		"",
	} {
		if _, err := (Jellyfin{}).ParseLine(line, now); !errors.Is(err, ingest.ErrSkip) {
			t.Errorf("%q: err = %v, want ErrSkip", line, err)
		}
	}
	if _, err := (Jellyfin{}).ParseLine(head+"x: Authentication request for a has been denied (IP: nope).", now); err == nil || errors.Is(err, ingest.ErrSkip) {
		t.Errorf("bad address: err = %v, want a parse error", err)
	}
}
