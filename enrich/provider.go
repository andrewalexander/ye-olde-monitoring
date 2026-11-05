package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// A queried provider answers about one indicator (or a batch) at a time, for
// a price in quota. Its answers are cached in the enrichment store; the cache
// is our local copy of its database.
type Queried interface {
	Name() string
	Handles(kind string) bool // "ip" or "domain"
	BatchSize() int           // most indicators per request (1: one at a time)
	// Lookup asks about inds (at most BatchSize). It returns an answer for
	// each indicator it learned anything about, found or not, and how many
	// quota units the request used.
	Lookup(ctx context.Context, inds []string) ([]Answer, int, error)
}

// Answer is what a queried provider said about one indicator.
type Answer struct {
	Indicator string
	Found     bool
	Facts     map[string]any  // the summary the explorer shows, labelled by provider
	Raw       json.RawMessage // the whole answer
}

// StopError means the provider refused (bad key, out of quota, not allowed):
// ask it nothing more this run.
type StopError struct {
	Provider string
	Status   int
	Message  string
}

func (e *StopError) Error() string {
	return fmt.Sprintf("%s refused (HTTP %d): %s", e.Provider, e.Status, e.Message)
}

// IsStop says whether err should stop a provider for the rest of a run.
func IsStop(err error) bool {
	var s *StopError
	return errors.As(err, &s)
}

// httpCaller does what every queried provider needs: one request at a time,
// at most one per MinGap, honouring 429 Retry-After a few times, and turning
// refusals into StopErrors.
type httpCaller struct {
	Provider string
	Client   *http.Client
	MinGap   time.Duration
	Sleep    func(context.Context, time.Duration) error // for tests
	last     time.Time
}

const maxTries = 3

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends req (rebuilt by mk for each try) and returns the status, headers
// and body. 404 and 2xx come back as-is; 429 is retried; any other 4xx is a
// StopError; 5xx and network errors are plain errors.
func (c *httpCaller) do(ctx context.Context, mk func() (*http.Request, error)) (int, http.Header, []byte, error) {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	for try := 1; ; try++ {
		if wait := c.MinGap - time.Since(c.last); !c.last.IsZero() && wait > 0 {
			if err := c.Sleep(ctx, wait); err != nil {
				return 0, nil, nil, err
			}
		}
		req, err := mk()
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("User-Agent", "dnscount-enrich/1")
		c.last = time.Now()
		resp, err := c.Client.Do(req.WithContext(ctx))
		if err != nil {
			return 0, nil, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			return 0, nil, nil, err
		}
		switch s := resp.StatusCode; {
		case s == http.StatusTooManyRequests && try < maxTries:
			wait := 5 * time.Second
			if try > 1 {
				wait = 30 * time.Second
			}
			if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n >= 0 && n <= 3600 {
				wait = time.Duration(n) * time.Second
			}
			if err := c.Sleep(ctx, wait); err != nil {
				return 0, nil, nil, err
			}
			continue
		case s >= 200 && s < 300, s == http.StatusNotFound:
			return s, resp.Header, body, nil
		case s >= 400 && s < 500:
			return s, resp.Header, body, &StopError{Provider: c.Provider, Status: s, Message: brief(body)}
		default:
			return s, resp.Header, body, fmt.Errorf("%s: HTTP %d: %s", c.Provider, s, brief(body))
		}
	}
}

// brief shortens an error body for logs and the Health page.
func brief(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
