package main

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
	"time"
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
