package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// MaxFeedSize caps one download.
const MaxFeedSize = 128 << 20

// FeedState is what `feeds update` remembers about each feed, in
// <dir>/state.json. The explorer reads it for freshness.
type FeedState struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	LastOK       time.Time `json:"last_ok,omitzero"`      // last 200 or 304
	LastChange   time.Time `json:"last_change,omitzero"` // last new file saved
	LastTry      time.Time `json:"last_try,omitzero"`
	LastError    string    `json:"last_error,omitempty"`
	Skipped      string    `json:"skipped,omitempty"` // why it wasn't fetched at all
	Entries      int       `json:"entries"`
}

// State maps feed name to its state.
type State map[string]*FeedState

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

// ReadState reads <dir>/state.json; a missing file is an empty state.
func ReadState(dir string) (State, error) {
	st := State{}
	b, err := os.ReadFile(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	return st, json.Unmarshal(b, &st)
}

func writeState(dir string, st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(statePath(dir), b)
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Stale says whether a feed has gone more than 3 intervals without a good fetch.
func (s *FeedState) Stale(f Feed, now time.Time) bool {
	if s == nil || s.Skipped != "" {
		return false
	}
	return s.LastOK.IsZero() || now.Sub(s.LastOK) > 3*f.Interval
}

var envRE = regexp.MustCompile(`\{([A-Z][A-Z0-9_]*)\}`)

// Fetcher downloads feeds into Dir.
type Fetcher struct {
	Dir    string
	Client *http.Client
	Now    func() time.Time
	Getenv func(string) string
	Log    func(format string, args ...any)
	// Force fetches every feed, even ones younger than their interval.
	Force bool
}

// Update fetches every feed that's due, keeping the old file whenever a new
// one fails, doesn't parse, or has fewer than half the entries it had.
// It returns the names of feeds whose file changed.
func (x *Fetcher) Update(ctx context.Context, feeds []Feed) (changed []string, err error) {
	if x.Now == nil {
		x.Now = time.Now
	}
	if x.Getenv == nil {
		x.Getenv = os.Getenv
	}
	if x.Client == nil {
		x.Client = &http.Client{Timeout: 5 * time.Minute}
	}
	if x.Log == nil {
		x.Log = func(string, ...any) {}
	}
	if err := os.MkdirAll(x.Dir, 0o750); err != nil {
		return nil, err
	}
	st, err := ReadState(x.Dir)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, f := range feeds {
		s := st[f.Name]
		if s == nil {
			s = &FeedState{}
			st[f.Name] = s
		}
		_, statErr := os.Stat(f.File(x.Dir))
		if !x.Force && statErr == nil && !s.LastOK.IsZero() && x.Now().Sub(s.LastOK) < f.Interval {
			continue
		}
		ok, err := x.fetch(ctx, f, s, statErr == nil)
		if err != nil {
			s.LastError = err.Error()
			x.Log("feed %s: %v", f.Name, err)
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
		} else if ok {
			changed = append(changed, f.Name)
		}
		if err := writeState(x.Dir, st); err != nil {
			return changed, err
		}
	}
	return changed, errors.Join(errs...)
}

func (x *Fetcher) fetch(ctx context.Context, f Feed, s *FeedState, haveFile bool) (changed bool, err error) {
	var missing []string
	u := envRE.ReplaceAllStringFunc(f.URL, func(m string) string {
		v := x.Getenv(m[1 : len(m)-1])
		if v == "" {
			missing = append(missing, m[1:len(m)-1])
		}
		return v
	})
	if len(missing) > 0 {
		s.Skipped = "needs " + strings.Join(missing, ", ")
		x.Log("feed %s: skipped, %s is not set", f.Name, strings.Join(missing, ", "))
		return false, nil
	}
	s.Skipped = ""
	s.LastTry = x.Now()
	var body []byte
	if !strings.Contains(u, "://") {
		if body, err = os.ReadFile(u); err != nil {
			return false, err
		}
	} else {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", "dnscount-feeds/1")
		if haveFile {
			if s.ETag != "" {
				req.Header.Set("If-None-Match", s.ETag)
			}
			if s.LastModified != "" {
				req.Header.Set("If-Modified-Since", s.LastModified)
			}
		}
		resp, err := x.Client.Do(req)
		if err != nil {
			return false, redact(err, u, f.URL)
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotModified && haveFile:
			s.LastOK, s.LastError = x.Now(), ""
			return false, nil
		case resp.StatusCode != http.StatusOK:
			return false, fmt.Errorf("HTTP %s", resp.Status)
		}
		body, err = io.ReadAll(io.LimitReader(resp.Body, MaxFeedSize+1))
		if err != nil {
			return false, redact(err, u, f.URL)
		}
		if len(body) > MaxFeedSize {
			return false, fmt.Errorf("bigger than %d MB", MaxFeedSize>>20)
		}
		s.ETag, s.LastModified = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	}
	n, err := countEntries(f, body)
	if err != nil {
		return false, fmt.Errorf("doesn't parse, kept the old file: %w", err)
	}
	if n == 0 || (s.Entries >= 20 && n < s.Entries/2) {
		return false, fmt.Errorf("only %d entries (had %d), kept the old file", n, s.Entries)
	}
	if err := writeAtomic(f.File(x.Dir), body); err != nil {
		return false, err
	}
	now := x.Now()
	s.LastOK, s.LastChange, s.LastError, s.Entries = now, now, "", n
	x.Log("feed %s: %d entries", f.Name, n)
	return true, nil
}

// redact keeps keys in URLs out of logs and state.
func redact(err error, filled, template string) error {
	if filled == template {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), filled, template))
}

func countEntries(f Feed, b []byte) (int, error) {
	if f.Format == "iptoasn" {
		t, err := ParseASN(b)
		if err != nil {
			return 0, err
		}
		return t.Entries, nil
	}
	l, err := ParseList(f, b)
	if err != nil {
		return 0, err
	}
	return l.Entries, nil
}
