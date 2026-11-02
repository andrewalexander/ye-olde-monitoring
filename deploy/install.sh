#!/bin/sh
# Install or upgrade dnscount on a systemd Linux host. Idempotent: re-run it
# to upgrade. It never overwrites /etc/dnscount/dnscount.env or the database.
#
#   sudo sh install.sh <dir containing dnscount binary, systemd/, dnscount.env.example>
#
# Usually run for you by `make deploy HOST=user@host`.
set -eu

SRC=${1:-$(dirname "$0")}
ENV=/etc/dnscount/dnscount.env

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd not found" >&2; exit 1; }
[ -x "$SRC/dnscount" ] || chmod +x "$SRC/dnscount"
"$SRC/dnscount" 2>&1 | grep -q 'usage: dnscount' || { echo "$SRC/dnscount doesn't run here (wrong ARCH?)" >&2; exit 1; }

# User: a plain system account, so `sudo -u dnscount dnscount report ...` works.
if ! id dnscount >/dev/null 2>&1; then
	useradd --system --user-group --home-dir /var/lib/dnscount --no-create-home --shell /usr/sbin/nologin dnscount
	echo "created user dnscount"
fi
if getent group caddy >/dev/null 2>&1; then
	usermod -aG caddy dnscount # read Caddy's access log
fi

# Binary: replace atomically so a running copy isn't disturbed mid-write.
install -m 0755 "$SRC/dnscount" /usr/local/bin/dnscount.new
mv -f /usr/local/bin/dnscount.new /usr/local/bin/dnscount

# Config: first install only.
install -d -m 0750 -o root -g dnscount /etc/dnscount
if [ ! -f "$ENV" ]; then
	token=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
	sed "s/^DNSCOUNT_TOKEN=.*/DNSCOUNT_TOKEN=$token/" "$SRC/dnscount.env.example" > "$ENV"
	chown root:dnscount "$ENV"
	chmod 0640 "$ENV"
	echo "wrote $ENV with a new /ingest token"
fi

# Units.
for u in dnscount-serve.service dnscount-caddy-log.service dnscount-syslog.service dnscount-backup.service dnscount-backup.timer; do
	install -m 0644 "$SRC/systemd/$u" /etc/systemd/system/$u
done
systemctl daemon-reload
systemctl enable --quiet dnscount-serve.service dnscount-backup.timer
systemctl restart dnscount-serve.service
systemctl start dnscount-backup.timer

# (Not sourced: values are systemd-style, unquoted with spaces.)
caddy_log=$(sed -n 's/^DNSCOUNT_CADDY_LOG=//p' "$ENV" | tail -1)
if [ -n "$caddy_log" ] && [ -f "$caddy_log" ]; then
	systemctl enable --quiet dnscount-caddy-log.service
	systemctl restart dnscount-caddy-log.service
	echo "tailing $caddy_log"
else
	echo "note: Caddy access log ${caddy_log:-(unset)} not found; dnscount-caddy-log.service not started."
	echo "      add the log block from deploy/Caddyfile.example, reload Caddy, then:"
	echo "      sudo systemctl enable --now dnscount-caddy-log.service"
fi

syslog_flags=$(sed -n 's/^DNSCOUNT_SYSLOG_FLAGS=//p' "$ENV" | tail -1)
if [ -n "$syslog_flags" ]; then
	systemctl enable --quiet dnscount-syslog.service
	systemctl restart dnscount-syslog.service
	echo "syslog receiver: dnscount syslog $syslog_flags"
else
	echo "note: DNSCOUNT_SYSLOG_FLAGS unset; dnscount-syslog.service not started."
fi

sleep 1
if systemctl is-active --quiet dnscount-serve.service; then
	echo
	echo "dnscount-serve is running. Quick checks on this host:"
	echo "  curl -s 'http://127.0.0.1:8080/counter.txt?site=test'"
	echo "  curl -s http://127.0.0.1:8081/api/health"
	echo "  sudo -u dnscount env DNSCOUNT_DB=/var/lib/dnscount/dnscount.db dnscount report hits -top ip"
	echo "  sudo grep DNSCOUNT_TOKEN $ENV    # token for RemoteSink"
else
	echo "dnscount-serve failed to start:" >&2
	journalctl -u dnscount-serve.service -n 30 --no-pager >&2
	exit 1
fi
