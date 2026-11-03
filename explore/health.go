package explore

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UnitSample is one systemd unit's cgroup numbers.
type UnitSample struct {
	CPU         float64 `json:"cpu_pct"`      // of one core, since the last sample
	Mem         int64   `json:"mem_bytes"`    // memory.current
	CPUPressure float64 `json:"cpu_pressure"` // cpu.pressure some avg10
	MemPressure float64 `json:"mem_pressure"` // memory.pressure some avg10
	IOPressure  float64 `json:"io_pressure"`  // io.pressure some avg10
	Present     bool    `json:"present"`
}

// Sample is one health reading.
type Sample struct {
	TS           time.Time             `json:"ts"`
	WALBytes     int64                 `json:"wal_bytes"`
	DBBytes      int64                 `json:"db_bytes"`
	PSI          map[string]float64    `json:"psi"` // cpu, memory, io: some avg10, percent
	Load1        float64               `json:"load1"`
	MemAvailable int64                 `json:"mem_available_bytes"`
	Units        map[string]UnitSample `json:"units"`
	Requests     int                   `json:"requests"` // since the last sample
	Timeouts     int                   `json:"timeouts"` // since the last sample
	QueryP95     float64               `json:"query_p95_ms"`
	QueryMax     float64               `json:"query_max_ms"`
	DNSAge       float64               `json:"dns_age_s"` // since the newest DNS lookup; -1 if none
	HitAge       float64               `json:"hit_age_s"` // since the newest hit; -1 if none
}

// SlowQuery is one of the slowest recent requests.
type SlowQuery struct {
	TS    time.Time `json:"ts"`
	Path  string    `json:"path"`
	Took  float64   `json:"took_ms"`
	Error string    `json:"error,omitempty"`
}

// Sampler reads system and per-unit contention, and keeps 24 hours of it.
type Sampler struct {
	ProcRoot   string   // "/proc"
	CgroupRoot string   // "/sys/fs/cgroup/system.slice"
	DB         string   // the live database file; its -wal sits next to it
	Units      []string // unit names, without .service
	// Newest returns the newest row times in dns_queries and hits.
	Newest func() (dns, hits time.Time, err error)
	Keep   time.Duration

	mu      sync.Mutex
	ring    []Sample
	prevCPU map[string]cpuMark
	pending []float64 // ms, since the last sample
	timeout int
	slow    []SlowQuery
}

type cpuMark struct {
	usec int64
	at   time.Time
}

// Observe records one API request.
func (s *Sampler) Observe(path string, took time.Duration, status int, err error) {
	ms := float64(took.Microseconds()) / 1000
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, ms)
	if status == 503 {
		s.timeout++
	}
	q := SlowQuery{TS: time.Now(), Path: path, Took: ms}
	if err != nil {
		q.Error = err.Error()
	}
	s.slow = append(s.slow, q)
	slices.SortFunc(s.slow, func(a, b SlowQuery) int {
		if a.Took > b.Took {
			return -1
		}
		if a.Took < b.Took {
			return 1
		}
		return 0
	})
	// Keep the 10 slowest of the last hour.
	cut := time.Now().Add(-time.Hour)
	s.slow = slices.DeleteFunc(s.slow, func(q SlowQuery) bool { return q.TS.Before(cut) })
	if len(s.slow) > 10 {
		s.slow = s.slow[:10]
	}
}

// Slow returns the slowest requests of the last hour.
func (s *Sampler) Slow() []SlowQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.slow)
}

// Take reads one sample and adds it to the ring.
func (s *Sampler) Take(now time.Time) Sample {
	smp := Sample{TS: now, PSI: map[string]float64{}, Units: map[string]UnitSample{}, DNSAge: -1, HitAge: -1}
	if fi, err := os.Stat(s.DB); err == nil {
		smp.DBBytes = fi.Size()
	}
	if fi, err := os.Stat(s.DB + "-wal"); err == nil {
		smp.WALBytes = fi.Size()
	}
	for _, r := range []string{"cpu", "memory", "io"} {
		if v, ok := readPSI(filepath.Join(s.ProcRoot, "pressure", r)); ok {
			smp.PSI[r] = v
		}
	}
	if b, err := os.ReadFile(filepath.Join(s.ProcRoot, "loadavg")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			smp.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	smp.MemAvailable = readMeminfo(filepath.Join(s.ProcRoot, "meminfo"), "MemAvailable") * 1024
	if s.Newest != nil {
		if d, h, err := s.Newest(); err == nil {
			if !d.IsZero() {
				smp.DNSAge = now.Sub(d).Seconds()
			}
			if !h.IsZero() {
				smp.HitAge = now.Sub(h).Seconds()
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prevCPU == nil {
		s.prevCPU = map[string]cpuMark{}
	}
	for _, u := range s.Units {
		dir := filepath.Join(s.CgroupRoot, u+".service")
		var us UnitSample
		if _, err := os.Stat(dir); err != nil {
			smp.Units[u] = us
			delete(s.prevCPU, u)
			continue
		}
		us.Present = true
		us.Mem = readInt(filepath.Join(dir, "memory.current"))
		us.CPUPressure, _ = readPSI(filepath.Join(dir, "cpu.pressure"))
		us.MemPressure, _ = readPSI(filepath.Join(dir, "memory.pressure"))
		us.IOPressure, _ = readPSI(filepath.Join(dir, "io.pressure"))
		if usec, ok := readKey(filepath.Join(dir, "cpu.stat"), "usage_usec"); ok {
			if p, ok := s.prevCPU[u]; ok && now.After(p.at) && usec >= p.usec {
				us.CPU = float64(usec-p.usec) / float64(now.Sub(p.at).Microseconds()) * 100
			}
			s.prevCPU[u] = cpuMark{usec, now}
		}
		smp.Units[u] = us
	}
	smp.Requests, smp.Timeouts = len(s.pending), s.timeout
	if len(s.pending) > 0 {
		slices.Sort(s.pending)
		smp.QueryP95 = s.pending[min(len(s.pending)-1, len(s.pending)*95/100)]
		smp.QueryMax = s.pending[len(s.pending)-1]
	}
	s.pending, s.timeout = s.pending[:0], 0
	keep := s.Keep
	if keep == 0 {
		keep = 24 * time.Hour
	}
	s.ring = append(s.ring, smp)
	cut := now.Add(-keep)
	i := 0
	for i < len(s.ring) && s.ring[i].TS.Before(cut) {
		i++
	}
	s.ring = s.ring[i:]
	return smp
}

// Latest is the newest sample, if any.
func (s *Sampler) Latest() (Sample, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) == 0 {
		return Sample{}, false
	}
	return s.ring[len(s.ring)-1], true
}

// Series returns the samples since `since`, thinned to at most max points
// by keeping each bucket's worst (largest) values.
func (s *Sampler) Series(since time.Time, max int) []Sample {
	s.mu.Lock()
	var in []Sample
	for _, smp := range s.ring {
		if !smp.TS.Before(since) {
			in = append(in, smp)
		}
	}
	s.mu.Unlock()
	if max <= 0 || len(in) <= max {
		return in
	}
	step := (len(in) + max - 1) / max
	var out []Sample
	for i := 0; i < len(in); i += step {
		out = append(out, worst(in[i:min(i+step, len(in))]))
	}
	return out
}

func worst(b []Sample) Sample {
	w := b[len(b)-1]
	w.PSI = map[string]float64{}
	w.Units = map[string]UnitSample{}
	for k, v := range b[len(b)-1].Units {
		w.Units[k] = v
	}
	w.Requests, w.Timeouts = 0, 0
	for _, s := range b {
		w.WALBytes = max(w.WALBytes, s.WALBytes)
		w.Load1 = max(w.Load1, s.Load1)
		w.QueryP95, w.QueryMax = max(w.QueryP95, s.QueryP95), max(w.QueryMax, s.QueryMax)
		w.DNSAge, w.HitAge = max(w.DNSAge, s.DNSAge), max(w.HitAge, s.HitAge)
		w.Requests += s.Requests
		w.Timeouts += s.Timeouts
		w.MemAvailable = min(w.MemAvailable, s.MemAvailable)
		for k, v := range s.PSI {
			w.PSI[k] = max(w.PSI[k], v)
		}
		for k, u := range s.Units {
			x := w.Units[k]
			x.CPU, x.Mem = max(x.CPU, u.CPU), max(x.Mem, u.Mem)
			x.CPUPressure, x.MemPressure, x.IOPressure = max(x.CPUPressure, u.CPUPressure),
				max(x.MemPressure, u.MemPressure), max(x.IOPressure, u.IOPressure)
			x.Present = x.Present || u.Present
			w.Units[k] = x
		}
	}
	return w
}

// readPSI reads "some avg10=..." from a pressure file.
func readPSI(path string) (float64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, f := range strings.Fields(line)[1:] {
			if v, ok := strings.CutPrefix(f, "avg10="); ok {
				n, err := strconv.ParseFloat(v, 64)
				return n, err == nil
			}
		}
	}
	return 0, false
}

func readInt(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// readKey reads "key value" lines (cpu.stat).
func readKey(path, key string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == key {
			n, err := strconv.ParseInt(f[1], 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// readMeminfo reads "Key:   123 kB" from /proc/meminfo, in kB.
func readMeminfo(path, key string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && k == key {
			if fs := strings.Fields(v); len(fs) > 0 {
				n, _ := strconv.ParseInt(fs[0], 10, 64)
				return n
			}
		}
	}
	return 0
}
