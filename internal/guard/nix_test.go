package guard

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// pathsRegex rebuilds a probe jail's failregex from one of nix/guard.nix's
// default path lists (probePathsCertain, probePaths), in the Go regexp
// dialect, minus <HOST> and the JSON around the path: what it's given is the
// path.
func pathsRegex(t *testing.T, option string) *regexp.Regexp {
	t.Helper()
	b, err := os.ReadFile("../../nix/guard.nix")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, option+" = mkOption")
	if i < 0 {
		t.Fatalf("no %s option", option)
	}
	j := strings.Index(s[i:], "default = [")
	k := strings.Index(s[i+j:], "];")
	var alts []string
	for _, m := range regexp.MustCompile(`(?m)^\s*''(.*)''\s*$`).FindAllStringSubmatch(s[i+j:i+j+k], -1) {
		alts = append(alts, strings.ReplaceAll(m[1], "%%", "%"))
	}
	if len(alts) == 0 {
		t.Fatalf("no %s defaults found", option)
	}
	// Go has no lookahead; (?=[/"?]|$) after an extension and (?!well-known/)
	// are rewritten to what they mean for a bare path.
	re := `(?i)^[^"?]*(?:` + strings.Join(alts, "|") + `)`
	re = strings.ReplaceAll(re, `(?=[/"?]|$)`, `(?:[/"?]|$)`)
	re = strings.ReplaceAll(re, `/\.(?!well-known/)`, `/\.(?:[^w]|w[^e]|we[^l])`)
	return regexp.MustCompile(re)
}

func TestProbePaths(t *testing.T) {
	certain, probe := pathsRegex(t, "probePathsCertain"), pathsRegex(t, "probePaths")
	// One of these is a ban.
	for _, p := range []string{
		"/.env", "/api/.env", "/.env.production", "/.git/config", "/.svn/wc.db", "/.ssh/id_rsa",
		"/wp-login.php", "/wp-config.php", "/phpinfo", "/_profiler/phpinfo", "/cgi-bin/luci",
		"/aws.json", "/config/aws.json", "/appsettings.Production.json", "/.docker/secrets.json",
		"/service-account.json", "/server.key", "/server.pem", "/cert.pem", "/config/credentials.yml.enc",
		"/_vti_pvt/service.pwd", "/_ignition/execute-solution", "/%2e%2e%2f%2eenv", "/var/task/x",
		"/cgi-bin/../../etc/passwd",
	} {
		if !certain.MatchString(p) {
			t.Errorf("%s: not caught by probePathsCertain", p)
		}
	}
	// Two of these in a day are a ban.
	for _, p := range []string{
		"/config.php", "/storage/logs/laravel.log", "/app/config/parameters.yml.dist", "/docker-compose.yml",
		"/database.sql", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/backup.zip", "/backup.tar.gz", "/site-backup.tgz", "/package-lock.json", "/composer.json",
		"/yarn.lock", "/bun.lock", "/Gemfile.lock", "/Pipfile.lock", "/go.sum", "/requirements.txt",
		"/config.xml", "/node_modules/", "/@vite/env",
	} {
		if !probe.MatchString(p) && !certain.MatchString(p) {
			t.Errorf("%s: not caught", p)
		}
	}
	// Seen from real clients on the server: Jellyfin's, and the explorer's.
	for _, p := range []string{
		"/web/config.json", "/config.json", "/web/index.html", "/web/node_modules.react-dom.bundle.js",
		"/node_modules.jquery.bundle.js", "/web/node_modules.%40mui.material.bundle.js",
		"/Users/AuthenticateByName", "/Items/abc/Images/Primary", "/.well-known/acme-challenge/x",
		"/.well-known/security.txt", "/static/js/main.chunk.js", "/System/Info/Public", "/socket",
		"/favicon.ico", "/touchicon.f5bbb798cb2c65908633.png", "/main.jellyfin.bundle.js",
		"/serviceworker.js", "/ui/vendor/tabulator.min.js", "/ui/vendor/tabulator.min.js.map",
		"/Videos/562d72520becb2de9c30ac8b2e32995d/stream.mp4", "/transmission/rpc",
	} {
		if certain.MatchString(p) || probe.MatchString(p) {
			t.Errorf("%s: a real client's request would count as a probe", p)
		}
	}
}
