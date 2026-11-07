#!/bin/sh
# Scripted check of the local compose stack (docker compose up / tilt up).
# Every step makes a request, then looks for it in the database.
set -eu
WEB=${WEB:-http://localhost:8000}
APP=${APP:-http://localhost:8001}
ADMIN=${ADMIN:-http://localhost:8081}
EXPLORE=${EXPLORE:-http://localhost:8090}
SITE=smoke-$(date +%s)
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# 1. Counter through Caddy counts, noinc doesn't.
for _ in 1 2 3; do curl -fsS -o /dev/null "$WEB/counter.svg?site=$SITE"; done
n=$(curl -fsS "$WEB/counter.txt?site=$SITE&noinc=1")
[ "$n" = 3 ] || fail "counter for $SITE is $n, want 3"
ok "counter: 3 loads -> $n"
curl -fsS "$WEB/counter.js" | grep -q currentScript || fail "counter.js"
curl -fsS "$WEB/" | grep -q 'counter.js' || fail "test page"
ok "test page and counter.js served"

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
