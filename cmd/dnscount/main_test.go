package main

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/ingest"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

func TestTailFollowsRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	write := func(flag int, s string) {
		f, err := os.OpenFile(path, flag|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(s)
		f.Close()
	}
	write(os.O_APPEND, "one\n")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&tailReader{path: path, f: f, poll: 10 * time.Millisecond})
	lines := make(chan string)
	go func() {
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	next := func(want string) {
		t.Helper()
		select {
		case got := <-lines:
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
	next("one")
	write(os.O_APPEND, "two\n")
	next("two")
	// Rename-and-recreate, like Caddy's roller.
	os.Rename(path, path+".1")
	write(os.O_APPEND, "three\n")
	next("three")
	// Truncate in place, like logrotate copytruncate.
	write(os.O_TRUNC, "four\n")
	next("four")
}

func TestReportFlags(t *testing.T) {
	db := filepath.Join(t.TempDir(), "t.db")
	for _, tc := range []struct {
		args    []string
		wantErr string
	}{
		{[]string{"hits", "path"}, `unexpected "path"`},
		{[]string{"hits", "-limit", "2", "method"}, `unexpected "method"`},
		{[]string{"dns", "domain"}, `unexpected "domain"`},
		{[]string{"trips", "extra"}, `unexpected "extra"`},
		{[]string{"hits", "-top", "ip", "-bottom", "ip"}, "only one of"},
		{[]string{"dns", "-top", "domain", "-new", "domain"}, "only one of"},
		{[]string{"dns", "-domain", "a.test", "-top", "client"}, "can't be combined"},
		{[]string{"dns", "-domain", "a.test", "-client", "10.0.0.1"}, "only one of"},
		{[]string{"dns"}, "needs -domain"},
		{[]string{"hits", "-top", "nonsense"}, "can't group"},
		{[]string{"hits", "-top", "path", "-ip", "10.0.0.1"}, ""},
		{[]string{"hits", "-bottom", "path"}, ""},
		{[]string{"hits", "-top", "path", "-status", "4xx"}, ""},
		{[]string{"hits", "-status", "404"}, ""},
		{[]string{"hits", "-status", "nope"}, "is not a code"},
		{[]string{"hits", "-bottom", "ua,method,path,ip"}, ""},
		{[]string{"hits", "-top", "ip,nonsense"}, "can't group"},
		{[]string{"dns", "-top", "domain,client"}, ""},
		{[]string{"hits", "-new", "ua"}, ""},
		{[]string{"dns", "-bottom", "client"}, ""},
		{[]string{"dns", "-new", "domain"}, ""},
		{[]string{"hits", "-ip", "10.0.0.1"}, ""},
	} {
		err := report(append(append([]string{}, tc.args[0], "-db", db), tc.args[1:]...))
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%v: %v", tc.args, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%v: error = %v, want %q", tc.args, err, tc.wantErr)
		}
	}
}

// An automatic run never spends Censys credits, even if the config lists
// Censys as automatic and a token is there.
func TestAutoNeverCallsCensys(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	dir := t.TempDir()
	db := filepath.Join(dir, "dnscount.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	st.InsertHits([]hit.Hit{{Hash: "h", TS: time.Now(), Site: "s", Source: "t", ClientIP: "185.242.226.118"}})
	st.InsertBan(ingest.Ban{TS: time.Now(), Event: "ban", Jail: "j", IP: "185.242.226.118"})
	st.Close()
	conf := filepath.Join(dir, "lookups.json")
	os.WriteFile(conf, []byte(`{"automatic":["censys"],"providers":{"censys":{"base":"`+srv.URL+`","daily":100}}}`), 0o600)
	keys := filepath.Join(dir, "keys.env")
	os.WriteFile(keys, []byte("CENSYS_TOKEN=tok\n"), 0o600)
	if err := lookupCmd(filepath.Join(dir, "explore.db"), db, "", true, false, "", 0, 7*24*time.Hour, keys, conf); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Errorf("an automatic run called censys %d times", hits.Load())
	}
}
