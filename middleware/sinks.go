package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andrewalexander/ye-olde-monitoring/hit"
	"github.com/andrewalexander/ye-olde-monitoring/internal/store"
)

// Sinks buffer hits and write them in batches from a background goroutine.
// If the buffer is full the hit is dropped: a slow database or collector
// must never slow the app. After failAfter consecutive failed writes the
// sink stops trying for pauseFor and drops everything meanwhile.
const (
	bufferSize = 4096
	batchSize  = 100
	failAfter  = 5
	pauseFor   = 30 * time.Second
)

type batcher struct {
	ch       chan hit.Hit
	flush    func([]hit.Hit) error
	interval time.Duration
	now      func() time.Time

	mu       sync.RWMutex
	closed   bool
	wg       sync.WaitGroup
	dropped  atomic.Int64
	paused   atomic.Int64 // unix nanos until which we don't try
	failures int
	lastErr  atomic.Value
}

func newBatcher(interval time.Duration, flush func([]hit.Hit) error) *batcher {
	b := &batcher{ch: make(chan hit.Hit, bufferSize), flush: flush, interval: interval, now: time.Now}
	b.wg.Add(1)
	go b.loop()
	return b
}

func (b *batcher) Record(h hit.Hit) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.now().UnixNano() < b.paused.Load() {
		b.dropped.Add(1)
		return
	}
	select {
	case b.ch <- h:
	default:
		b.dropped.Add(1)
	}
}

func (b *batcher) loop() {
	defer b.wg.Done()
	t := time.NewTicker(b.interval)
	defer t.Stop()
	var batch []hit.Hit
	send := func() {
		if len(batch) == 0 {
			return
		}
		if b.now().UnixNano() < b.paused.Load() {
			b.dropped.Add(int64(len(batch)))
		} else if err := b.flush(batch); err != nil {
			b.lastErr.Store(err.Error())
			b.dropped.Add(int64(len(batch)))
			if b.failures++; b.failures >= failAfter {
				b.failures = 0
				b.paused.Store(b.now().Add(pauseFor).UnixNano())
			}
		} else {
			b.failures = 0
		}
		batch = batch[:0]
	}
	for {
		select {
		case h, ok := <-b.ch:
			if !ok {
				send()
				return
			}
			if batch = append(batch, h); len(batch) >= batchSize {
				send()
			}
		case <-t.C:
			send()
		}
	}
}

// Close flushes what's buffered and stops the sink.
func (b *batcher) Close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.ch)
	}
	b.mu.Unlock()
	b.wg.Wait()
}

// SinkStats is for health checks.
type SinkStats struct {
	Dropped     int64     `json:"dropped"`
	PausedUntil time.Time `json:"paused_until,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

func (b *batcher) Stats() SinkStats {
	s := SinkStats{Dropped: b.dropped.Load()}
	if p := b.paused.Load(); p > b.now().UnixNano() {
		s.PausedUntil = time.Unix(0, p)
	}
	s.LastError, _ = b.lastErr.Load().(string)
	return s
}

// LocalSink writes hits to a store in the same process.
type LocalSink struct{ *batcher }

func NewLocalSink(st *store.Store) *LocalSink {
	return &LocalSink{newBatcher(time.Second, func(hs []hit.Hit) error {
		_, err := st.InsertHits(hs)
		return err
	})}
}

// RemoteSink POSTs batches of hits to a collector's /ingest.
type RemoteSink struct{ *batcher }

func NewRemoteSink(url, token string) *RemoteSink {
	client := &http.Client{Timeout: 5 * time.Second}
	return &RemoteSink{newBatcher(2*time.Second, func(hs []hit.Hit) error {
		body, err := json.Marshal(IngestBatch{Hits: hs})
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("collector: %s: %s", resp.Status, bytes.TrimSpace(msg))
		}
		return nil
	})}
}

// IngestBatch is the /ingest request body.
type IngestBatch struct {
	Hits []hit.Hit `json:"hits"`
}
