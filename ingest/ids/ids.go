// Package ids parses UniFi intrusion detection/prevention (IDS/IPS) alerts
// into ingest.IDSAlert records.
package ids

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dnscount/ingest"
)

// UniFi reads both forms a UniFi gateway produces:
//
// The Suricata alert JSON in the router's /var/log/ulog/threat.log:
//
//	2026-11-02T21:31:20-05:00 Router Router ubnt-idsips-daemon[8313]: {"alert":{"action":"allowed","signature":"ET DROP ...",...},"src_ip":...}
//
// The CEF events the Network app sends to a SIEM server (Settings → remote
// logging, with security events on):
//
//	<14>Nov 02 21:31:20 Router CEF:0|Ubiquiti|UniFi Network|10.0|...|Threat Detected and Blocked|7|src=203.0.113.5 spt=4444 dst=192.168.1.10 dpt=443 proto=TCP UNIFIipsSignature=ET DROP ... UNIFIipsSignatureId=2402000 ...
//
// Other CEF events (logins, device changes, the "Test Syslog" button) are
// skipped.
type UniFi struct{}

func (UniFi) ParseLine(line string, now time.Time) (ingest.Record, error) {
	if prefix, body, ok := strings.Cut(line, "CEF:"); ok {
		return parseCEF(prefix, body, now)
	}
	h, err := ingest.ParseHeader(line, now)
	if err != nil || h.Prog != "ubnt-idsips-daemon" {
		return ingest.Record{}, ingest.ErrSkip
	}
	return parseSuricata(h)
}

type eve struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     *struct {
		Action      string `json:"action"`
		Signature   string `json:"signature"`
		SignatureID int64  `json:"signature_id"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

func parseSuricata(h ingest.Header) (ingest.Record, error) {
	var e eve
	if err := json.Unmarshal([]byte(strings.TrimSpace(h.Msg)), &e); err != nil {
		return ingest.Record{}, errors.New("ubnt-idsips-daemon line without valid JSON")
	}
	if e.Alert == nil {
		return ingest.Record{}, ingest.ErrSkip
	}
	a := &ingest.IDSAlert{
		TS: h.TS, SrcIP: e.SrcIP, SrcPort: e.SrcPort, DstIP: e.DestIP, DstPort: e.DestPort,
		Proto: strings.ToLower(e.Proto), Action: e.Alert.Action, Signature: e.Alert.Signature,
		SignatureID: e.Alert.SignatureID, Category: e.Alert.Category, Severity: e.Alert.Severity,
		Source: "unifi-ids",
	}
	// Suricata's own timestamp has microseconds; the syslog one may not.
	if ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", e.Timestamp); err == nil {
		a.TS = ts
	}
	return finish(a)
}

// cefKeyRE finds where each extension key starts. Values can contain spaces,
// so a value runs until the next key. An escaped \= is never a key's =,
// because \ isn't a key character.
var cefKeyRE = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_.]+)=`)

var cefUnescape = strings.NewReplacer(`\=`, `=`, `\\`, `\`, `\n`, "\n", `\r`, "\r", `\|`, `|`)

func parseCEF(prefix, body string, now time.Time) (ingest.Record, error) {
	// Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
	head, ext, ok := splitCEFHeader(body)
	if !ok {
		return ingest.Record{}, errors.New("CEF line with a short header")
	}
	kv := map[string]string{}
	locs := cefKeyRE.FindAllStringSubmatchIndex(ext, -1)
	for i, m := range locs {
		end := len(ext)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		kv[ext[m[2]:m[3]]] = cefUnescape.Replace(strings.TrimSpace(ext[m[1]:end]))
	}
	name := head[5]
	if kv["UNIFIipsSignature"] == "" && !strings.Contains(name, "Threat") && !strings.Contains(name, "Honeypot") {
		return ingest.Record{}, ingest.ErrSkip
	}
	a := &ingest.IDSAlert{
		SrcIP: kv["src"], DstIP: kv["dst"], Proto: strings.ToLower(kv["proto"]),
		Action: "allowed", Signature: kv["UNIFIipsSignature"], Category: kv["UNIFIipsClass"],
		Source: "unifi-cef",
	}
	if strings.Contains(strings.ToLower(name), "blocked") || strings.EqualFold(kv["act"], "blocked") {
		a.Action = "blocked"
	}
	if a.Signature == "" {
		a.Signature = name
	}
	if a.Category == "" {
		a.Category = kv["UNIFIipsClassDescription"]
	}
	if a.SrcIP == "" {
		a.SrcIP = kv["UNIFIsrcClientIp"]
	}
	if a.DstIP == "" {
		a.DstIP = kv["UNIFIdstClientIp"]
	}
	a.SrcPort, _ = strconv.Atoi(kv["spt"])
	a.DstPort, _ = strconv.Atoi(kv["dpt"])
	a.SignatureID, _ = strconv.ParseInt(kv["UNIFIipsSignatureId"], 10, 64)
	a.Severity, _ = strconv.Atoi(head[6])
	// The syslog header carries the time; with none, it's now (it came over
	// the network just now). UNIFIutcTime, when present, is the event's own.
	a.TS = now
	if h, err := ingest.ParseHeader(strings.TrimSpace(prefix)+" cef: -", now); err == nil && !h.TS.IsZero() {
		a.TS = h.TS
	}
	if ts, ok := parseUTCTime(kv["UNIFIutcTime"]); ok {
		a.TS = ts
	}
	return finish(a)
}

// splitCEFHeader splits the seven header fields from the extension, honouring
// \| escapes inside header fields.
func splitCEFHeader(s string) ([]string, string, bool) {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
		case s[i] == '|':
			fields = append(fields, cur.String())
			cur.Reset()
			if len(fields) == 7 {
				return fields, s[i+1:], true
			}
		default:
			cur.WriteByte(s[i])
		}
	}
	return nil, "", false
}

func parseUTCTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 1e12 {
		return time.UnixMilli(ms).UTC(), true
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// finish normalizes the addresses. An alert without a valid source is no use
// to anyone, so it counts as bad; a missing destination is allowed (some
// honeypot events have none).
func finish(a *ingest.IDSAlert) (ingest.Record, error) {
	src, err := netip.ParseAddr(a.SrcIP)
	if err != nil {
		return ingest.Record{}, errors.New("IDS alert without a valid source address")
	}
	a.SrcIP = src.String()
	if dst, err := netip.ParseAddr(a.DstIP); err == nil {
		a.DstIP = dst.String()
	} else {
		a.DstIP = ""
	}
	if a.Action == "" {
		a.Action = "allowed"
	}
	return ingest.Record{Alert: a}, nil
}
