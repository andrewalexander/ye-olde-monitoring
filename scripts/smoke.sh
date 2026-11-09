#!/bin/sh
# Scripted check of the local compose stack (docker compose up / tilt up).
# Every step makes a request, then looks for it in the database.
set -eu
WEB=${WEB:-http://localhost:8000}
APP=${APP:-http://localhost:8001}
STATIC=${STATIC:-http://localhost:8002}
ADMIN=${ADMIN:-http://localhost:8081}
EXPLORE=${EXPLORE:-http://localhost:8090}
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# wait_hit QUERY GREP: poll the explorer until a hit matching GREP shows up.
wait_hit() {
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		curl -fsS "$EXPLORE/api/hits?since=10m&limit=200$1" | grep -q "$2" && return 0
		sleep 1
	done
	return 1
}
counter() { curl -fsS "$STATIC/counter.txt?site=caddy-site"; }

# 1. examples/caddy-site: a page load lands in Caddy's log, the counter is
#    computed from it, and reloads by the same visitor don't raise it.
m1=smoke-$$-$(date +%s)
curl -fsS "$STATIC/?v=$m1" | grep -q 'counter.svg?site=caddy-site' || fail "caddy-site page"
wait_hit "&site=caddy-site" "v=$m1" || fail "caddy-site hit never arrived"
sleep 3 # -counter-ttl 2s in docker-compose.yml
n=$(counter)
[ "$n" -ge 1 ] || fail "caddy-site counter is $n after a page load"
for i in 1 2 3; do curl -fsS -o /dev/null "$STATIC/about?v=$m1-$i"; done
wait_hit "&site=caddy-site" "v=$m1-3" || fail "caddy-site reloads never arrived"
sleep 3
[ "$(counter)" = "$n" ] || fail "reloads changed the counter from $n to $(counter)"
ok "counter from Caddy's log: $n, unchanged by reloads"
code=$(curl -s -o /dev/null -w '%{http_code}' "$STATIC/counter.svg?site=not-listed")
[ "$code" = 404 ] || fail "counter for an unlisted site: $code, want 404"
curl -fsS "$WEB/counter.svg?site=localhost" | grep -q '<svg' || fail "test page counter"
ok "counter: unlisted site 404s; test page counter served"

# 2. Caddy access log -> caddy-log tailer -> hits.
marker=smoke-$$-$(date +%s)
curl -s -o /dev/null "$WEB/missing-$marker"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	curl -fsS "$EXPLORE/api/hits?since=10m&limit=200" | grep -q "missing-$marker" && break
	sleep 1
done
curl -fsS "$EXPLORE/api/hits?since=10m&limit=200" | grep -q "missing-$marker" || fail "Caddy log hit for /missing-$marker never arrived"
ok "Caddy access log hit recorded (404 /missing-$marker)"

# 3. Go middleware -> RemoteSink -> /ingest.
curl -fsS -o /dev/null "$APP/?from=$marker"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	curl -fsS "$EXPLORE/api/hits?site=example&since=10m&limit=200" | grep -q "from=$marker" && break
	sleep 1
done
curl -fsS "$EXPLORE/api/hits?site=example&since=10m&limit=200" | grep -q "from=$marker" || fail "middleware hit never arrived"
ok "example app hit recorded via /ingest"

# 4. Garbage to /ingest from a fresh-looking client trips the breaker.
#    (Caddy sets X-Forwarded-For itself, so this is your real address.)
codes=""
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
	codes="$codes $(curl -s -o /dev/null -w '%{http_code}' -X POST --data "{junk$i" "$WEB/ingest")"
done
case "$codes" in *429*) ok "garbage to /ingest:$codes" ;; *) fail "no 429 in:$codes (already tripped earlier? wait a minute and rerun)" ;; esac
sleep 1
curl -fsS "$EXPLORE/api/trips?since=10m" | grep -q '"breaker"' || fail "no trip row"
ok "breaker trip recorded"

# 5. Sanity checks over everything stored.
curl -fsS "$ADMIN/api/health" | grep -Eq '"data_problems": ?(null|\[\])' || fail "data problems: $(curl -fsS "$ADMIN/api/health")"
ok "check: no data problems"
echo "all good. Reports: docker compose exec dnscount dnscount report hits -top ip"
