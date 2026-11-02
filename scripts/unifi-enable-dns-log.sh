#!/bin/sh
# Turn on dnsmasq query logging on a UniFi OS gateway so its remote syslog
# carries DNS lookups for `dnscount syslog`.
#
# Run it on the router:
#   ssh root@<router> 'sh -s' < scripts/unifi-enable-dns-log.sh
#   ssh root@<router> 'sh -s' -- --off < scripts/unifi-enable-dns-log.sh   # undo
#
# CAVEATS (verify on your device before relying on this):
#   - UniFi OS generates dnsmasq config itself. The drop-in directory below
#     is where current UniFi OS gateways keep it, but it lives on a tmpfs, so
#     a reboot or firmware update wipes this change. Re-run the script, or
#     hook it into an on-boot mechanism.
#   - Query logging is chatty. That's fine for syslog forwarding, but it
#     also grows the router's local logs.
#   - Make sure Remote Logging (syslog / SIEM) is on in UniFi Network and
#     points at the host running `dnscount syslog`.
set -eu

NAME=zz-dnscount-log-queries.conf

dir=""
for d in /run/dnsmasq.conf.d /run/dnsmasq.dhcp.conf.d /etc/dnsmasq.d; do
	if [ -d "$d" ]; then dir=$d; break; fi
done
if [ -z "$dir" ]; then
	echo "no dnsmasq conf dir found; look for one with: ps w | grep dnsmasq  (the --conf-dir= flag)" >&2
	exit 1
fi

if [ "${1:-}" = "--off" ]; then
	rm -f "$dir/$NAME"
	echo "removed $dir/$NAME"
else
	# log-queries=extra adds a per-query serial number, so two identical
	# lookups in the same second can still be told apart.
	printf 'log-queries=extra\n' > "$dir/$NAME"
	echo "wrote $dir/$NAME"
fi

# dnsmasq only reads config at startup. UniFi's supervisor restarts it when
# it exits.
if pkill -x dnsmasq; then
	echo "restarted dnsmasq; give it a few seconds to come back"
else
	echo "dnsmasq wasn't running? check: ps w | grep dnsmasq" >&2
fi
