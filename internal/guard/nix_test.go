package guard

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// probeRegex rebuilds the caddy-probe failregex from nix/guard.nix's default
// probePaths, in the Go regexp dialect, minus <HOST> and the JSON around the
// path: what it's given is the path.
func probeRegex(t *testing.T) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile("../../nix/guard.nix")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "probePaths = mkOption")
	j := strings.Index(s[i:], "default = [")
	k := strings.Index(s[i+j:], "];")
	var alts []string
	for _, m := range regexp.MustCompile(`(?m)^\s*''(.*)''\s*$`).FindAllStringSubmatch(s[i+j:i+j+k], -1) {
		alts = append(alts, strings.ReplaceAll(m[1], "%%", "%"))
	}
	if len(alts) == 0 {
		t.Fatal("no probePaths defaults found")
	}
	// Go has no lookahead; (?=[/"?]|$) after an extension and (?!well-known/)
	// are rewritten to what they mean for a bare path.
	re := `(?i)^[^"?]*(?:` + strings.Join(alts, "|") + `)`
	re = strings.ReplaceAll(re, `(?=[/"?]|$)`, `(?:[/"?]|$)`)
	re = strings.ReplaceAll(re, `/\.(?!well-known/)`, `/\.(?:[^w]|w[^e]|we[^l])`)
	return regexp.MustCompile(re)
}

func TestProbePaths(t *testing.T) {
	re := probeRegex(t)
	for _, p := range []string{
		"/.env", "/.git/config", "/wp-login.php", "/phpinfo", "/_profiler/phpinfo",
		"/aws.json", "/config/aws.json", "/appsettings.Production.json", "/.docker/secrets.json",
		"/storage/logs/laravel.log", "/app/config/parameters.yml.dist", "/var/task/x",
	} {
		if !re.MatchString(p) {
			t.Errorf("%s: not caught", p)
		}
	}
	// Seen from real Jellyfin clients on the server.
	for _, p := range []string{
		"/web/config.json", "/web/index.html", "/web/node_modules.react-dom.bundle.js",
		"/web/node_modules.%40mui.material.bundle.js", "/Users/AuthenticateByName",
		"/Items/abc/Images/Primary", "/.well-known/acme-challenge/x", "/static/js/main.chunk.js",
		"/System/Info/Public", "/socket",
	} {
		if re.MatchString(p) {
			t.Errorf("%s: a real client's request would count as a probe", p)
		}
	}
}
