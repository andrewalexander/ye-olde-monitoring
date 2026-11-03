#!/bin/sh
# Logs a UniFi OS gateway's neighbour tables (ARP for IPv4, NDP for IPv6) to
# its syslog, which forwards them to dnscount. That's how dnscount names
# IPv6 devices: DHCP never sees their self-assigned addresses, but the MAC
# here links them to the name DHCP or UniFi gave the same device.
#
# Run it on the router; run it again to upgrade:
#   ssh root@<router> 'sh -s' < scripts/unifi-neighbors.sh
#   ssh root@<router> 'sh -s' -- --off < scripts/unifi-neighbors.sh   # undo
#
# What it installs:
#   /data/dnscount-neigh/   neigh.sh and its state (kept apart from
#                           scripts/unifi-dns-blocking.sh, whose --off removes
#                           /data/dnscount)
#   dnscount-neigh          every minute: logs entries that are new or whose
#                           MAC changed, and every entry once an hour, as
#                             dnscount-neigh: ip=<ip> mac=<mac> dev=<br0> state=<STALE>
#
# Only LAN bridges (br*) are logged, never the WAN side, and no link-local
# (fe80::) addresses. Nothing leaves the router except over the remote
# syslog it already sends to dnscount.
#
# CAVEAT: not supported by UniFi. A firmware update may remove the systemd
# units; re-run this script after updating.
set -eu

DIR=/data/dnscount-neigh
UNITS=/etc/systemd/system

if [ "${1:-}" = "--off" ]; then
	systemctl disable --now dnscount-neigh.timer 2>/dev/null || true
	rm -f "$UNITS"/dnscount-neigh.*
	systemctl daemon-reload
	rm -rf "$DIR"
	echo "removed"
	exit 0
fi

mkdir -p "$DIR"

cat > "$DIR/neigh.sh" <<'NEIGH'
#!/bin/sh
# Log new or changed neighbour entries; all of them on the first run of each hour.
set -eu
DIR=/data/dnscount-neigh
hour=$(date +%Y%m%d%H)
[ -f "$DIR/last" ] || : > "$DIR/last"
cur=$(mktemp "$DIR/cur.XXXXXX")
trap 'rm -f "$cur"' EXIT
{ ip -4 neigh show; ip -6 neigh show; } | awk '
	{
		ip = $1; dev = ""; mac = ""; state = $NF
		for (i = 2; i < NF; i++) {
			if ($i == "dev") dev = $(i + 1)
			if ($i == "lladdr") mac = $(i + 1)
		}
		if (mac == "" || dev !~ /^br/ || ip ~ /^fe80:/) next
		print ip, mac, dev, state
	}' | sort -u > "$cur"
if [ "$(cat "$DIR/hour" 2>/dev/null || true)" = "$hour" ]; then
	# Only pairs we haven't logged as they are now.
	todo=$(awk 'NR == FNR { seen[$1 " " $2] = 1; next } !(($1 " " $2) in seen)' "$DIR/last" "$cur")
else
	todo=$(cat "$cur")
	echo "$hour" > "$DIR/hour"
fi
printf '%s\n' "$todo" | while read -r ip mac dev state; do
	[ -n "$ip" ] || continue
	logger -t dnscount-neigh -p user.info "ip=$ip mac=$mac dev=$dev state=$state"
done
mv "$cur" "$DIR/last"
trap - EXIT
NEIGH
chmod 0755 "$DIR/neigh.sh"

cat > "$UNITS/dnscount-neigh.service" <<'EOF'
[Unit]
Description=dnscount: log the neighbour tables (IP to MAC) for naming LAN devices

[Service]
Type=oneshot
ExecStart=/data/dnscount-neigh/neigh.sh
EOF

cat > "$UNITS/dnscount-neigh.timer" <<'EOF'
[Unit]
Description=Log neighbour-table changes every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
"$DIR/neigh.sh"
systemctl enable --now dnscount-neigh.timer

echo "installed; logged $(wc -l < "$DIR/last") neighbour entries"
