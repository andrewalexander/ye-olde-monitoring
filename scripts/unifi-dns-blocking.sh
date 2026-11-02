#!/bin/sh
# DNS query logging and ad blocking in a UniFi OS gateway's own dnsmasq, using
# HaGeZi's lists. Replaces scripts/unifi-enable-dns-log.sh and UniFi's Ad
# Blocking, which hides the real client from dnsmasq's log (see docs/homelab.md).
#
# Run it on the router; run it again to change the lists or upgrade:
#   ssh root@<router> 'sh -s' < scripts/unifi-dns-blocking.sh
#   ssh root@<router> 'sh -s' -- --off < scripts/unifi-dns-blocking.sh   # undo
#
# What it installs:
#   /data/dnscount/         lists, blocklist.txt, allowlist.txt, update.sh, ensure.sh
#   dnscount-dns-ensure     every minute: puts the dnsmasq drop-in back if a
#                           reboot or UniFi removed it
#   dnscount-dns-update     nightly: refreshes the lists, restarts dnsmasq if
#                           they changed
#
# To let a blocked site through, add its domain to
# /data/dnscount/allowlist.txt and run /data/dnscount/update.sh.
#
# CAVEATS:
#   - This isn't supported by UniFi. A firmware update may remove the systemd
#     units, and then blocking and logging stop with DNS still working. Re-run
#     this script after updating.
#   - The drop-in only affects the main dnsmasq. UniFi's per-WAN instance (port
#     20201) can't be given one; it's only used by WAN-specific traffic policies.
set -eu

DIR=/data/dnscount
UNITS=/etc/systemd/system
DROPIN=/run/dnsmasq.dhcp.conf.d/zz-dnscount.conf
OLD_DROPIN=/run/dnsmasq.dhcp.conf.d/zz-dnscount-log-queries.conf

if [ "${1:-}" = "--off" ]; then
	systemctl disable --now dnscount-dns-ensure.timer dnscount-dns-update.timer 2>/dev/null || true
	rm -f "$UNITS"/dnscount-dns-ensure.* "$UNITS"/dnscount-dns-update.*
	systemctl daemon-reload
	rm -f "$DROPIN" "$OLD_DROPIN"
	rm -rf "$DIR"
	pkill -x dnsmasq || true
	echo "removed; dnsmasq is restarting without logging or blocking"
	exit 0
fi

mkdir -p "$DIR/lists"

# Pro is the baseline. The rest cover what it leaves out.
cat > "$DIR/lists.txt" <<'EOF'
pro
fake
hoster
native.apple
native.huawei
native.oppo-realme
native.roku
popupads
EOF

# Your own additions, one domain per line, with its subdomains. Edit them here
# and re-run this script, so they survive a firmware update.
cat > "$DIR/blocklist.txt" <<'EOF'
aviro2003.boom.ru
EOF

if [ ! -f "$DIR/allowlist.txt" ]; then
	cat > "$DIR/allowlist.txt" <<'EOF'
# One domain per line, with its subdomains. These are never blocked.
# Run /data/dnscount/update.sh after editing.
EOF
fi

cat > "$DIR/update.sh" <<'UPDATE'
#!/bin/sh
# Download the lists, build blocklist.conf, and restart dnsmasq if it changed.
set -eu

DIR=/data/dnscount
BASE=https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/dnsmasq
TMP=/run/dnscount-update
# Below this, pro.txt is a broken download rather than a real list.
MIN_PRO=100000

# dnsmasq config can run commands as root (dhcp-script) or reroute a domain
# (server=). Only this exact shape is ever loaded from a download.
LINE='^local=/[a-z0-9_-]+(\.[a-z0-9_-]+)+/$'
export LC_ALL=C

log() { logger -t dnscount-dns "$*" 2>/dev/null || true; echo "$*"; }

rm -rf "$TMP"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# Each failure keeps that list's last good copy.
fetch() {
	name=$1
	if ! curl -fsS --retry 2 --max-time 120 -o "$TMP/raw" "$BASE/$name.txt"; then
		log "$name: download failed, keeping the last copy"
		return 0
	fi
	if grep -vE "^(#.*)?$|$LINE" "$TMP/raw" | grep -q .; then
		log "$name: REFUSED, contains lines that aren't local=/domain/"
		return 0
	fi
	grep -E "$LINE" "$TMP/raw" > "$TMP/filtered" || true
	new=$(wc -l < "$TMP/filtered")
	old=0
	[ -f "$DIR/lists/$name.txt" ] && old=$(wc -l < "$DIR/lists/$name.txt")
	if [ "$new" -lt 1 ] || [ "$new" -lt $((old / 2)) ] || { [ "$name" = pro ] && [ "$new" -lt "$MIN_PRO" ]; }; then
		log "$name: REFUSED, $new entries (had $old)"
		return 0
	fi
	cp "$TMP/filtered" "$TMP/$name.new"
	mv "$TMP/$name.new" "$DIR/lists/$name.txt"
}

: > "$TMP/merged"
while read -r name; do
	[ -n "$name" ] || continue
	fetch "$name"
	[ -f "$DIR/lists/$name.txt" ] && cat "$DIR/lists/$name.txt" >> "$TMP/merged"
done < "$DIR/lists.txt"

if [ ! -f "$DIR/lists/pro.txt" ]; then
	log "no usable pro list; leaving blocklist.conf alone"
	exit 1
fi

grep -E '^[a-z0-9_-]+(\.[a-z0-9_-]+)+$' "$DIR/blocklist.txt" | sed 's|.*|local=/&/|' >> "$TMP/merged" || true

# local=/parent/ blocks subdomains too, so server=/domain/# (use the normal
# upstreams) is what lets a domain through, however its parents are listed.
sort -u "$TMP/merged" > "$TMP/candidate"
: > "$TMP/allow"
grep -E '^[a-z0-9_-]+(\.[a-z0-9_-]+)+$' "$DIR/allowlist.txt" > "$TMP/allow" || true
if [ -s "$TMP/allow" ]; then
	sed 's|.*|local=/&/|' "$TMP/allow" > "$TMP/remove"
	grep -vxFf "$TMP/remove" "$TMP/candidate" > "$TMP/kept" || true
	sed 's|.*|server=/&/#|' "$TMP/allow" >> "$TMP/kept"
	mv "$TMP/kept" "$TMP/candidate"
fi

if ! dnsmasq --test --conf-file="$TMP/candidate" >/dev/null 2>&1; then
	log "new blocklist failed dnsmasq --test; leaving the old one"
	exit 1
fi

if cmp -s "$TMP/candidate" "$DIR/blocklist.conf"; then
	log "blocklist unchanged ($(wc -l < "$TMP/candidate") lines)"
	exit 0
fi

cp "$TMP/candidate" "$DIR/blocklist.conf.new"
mv "$DIR/blocklist.conf.new" "$DIR/blocklist.conf"
rm -f "$DIR/disabled"
log "blocklist updated ($(wc -l < "$DIR/blocklist.conf") lines)"
"$DIR/ensure.sh" --restart
UPDATE

cat > "$DIR/ensure.sh" <<'ENSURE'
#!/bin/sh
# Keep the dnsmasq drop-in in place. /run is empty after a reboot, and dnsmasq
# only reads config at startup, so a missing or wrong file means a restart.
set -eu

DIR=/data/dnscount
CONFDIR=/run/dnsmasq.dhcp.conf.d
DROPIN=$CONFDIR/zz-dnscount.conf

log() { logger -t dnscount-dns "$*" 2>/dev/null || true; echo "$*"; }

# UniFi hasn't started dnsmasq yet. The next run will catch it.
[ -d "$CONFDIR" ] || exit 0

if [ ! -s "$DIR/blocklist.conf" ]; then
	systemctl start --no-block dnscount-dns-update.service 2>/dev/null || true
fi

want='log-queries=extra'
if [ -s "$DIR/blocklist.conf" ] && [ ! -e "$DIR/disabled" ]; then
	want="$want
conf-file=$DIR/blocklist.conf"
fi

restart=${1:-}
if [ "$(cat "$DROPIN" 2>/dev/null || true)" != "$want" ]; then
	printf '%s\n' "$want" > "$DROPIN"
	restart=--restart
fi
[ "$restart" = --restart ] || exit 0

main_running() { pgrep -f dnsmasq-main.pid >/dev/null; }

pkill -x dnsmasq || true
sleep 3
i=0
while [ $i -lt 20 ]; do
	if main_running; then
		# Started isn't enough: make sure it stays up.
		sleep 5
		main_running && exit 0
	fi
	i=$((i + 1))
	sleep 1
done

# Never leave the house without DNS because of a blocklist.
log "dnsmasq didn't come back with the blocklist; disabling blocking"
touch "$DIR/disabled"
printf 'log-queries=extra\n' > "$DROPIN"
pkill -x dnsmasq || true
exit 1
ENSURE

chmod 0755 "$DIR/update.sh" "$DIR/ensure.sh"

cat > "$UNITS/dnscount-dns-ensure.service" <<'EOF'
[Unit]
Description=dnscount: keep the dnsmasq logging and blocklist drop-in in place

[Service]
Type=oneshot
ExecStart=/data/dnscount/ensure.sh
EOF

cat > "$UNITS/dnscount-dns-ensure.timer" <<'EOF'
[Unit]
Description=Check the dnsmasq drop-in every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF

cat > "$UNITS/dnscount-dns-update.service" <<'EOF'
[Unit]
Description=dnscount: refresh the DNS blocklists
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/data/dnscount/update.sh
EOF

cat > "$UNITS/dnscount-dns-update.timer" <<'EOF'
[Unit]
Description=Refresh the DNS blocklists nightly

[Timer]
OnCalendar=*-*-* 04:30:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

rm -f "$OLD_DROPIN"
systemctl daemon-reload
"$DIR/update.sh"
"$DIR/ensure.sh"
systemctl enable --now dnscount-dns-ensure.timer dnscount-dns-update.timer

echo
echo "installed. Lines in blocklist.conf: $(wc -l < "$DIR/blocklist.conf")"
echo "dnsmasq memory: $(ps -o rss= -p "$(pgrep -f dnsmasq-main.pid | head -1)" 2>/dev/null || echo '?') KiB"
echo "Clients only reach this dnsmasq directly once UniFi's Ad Blocking is off."
