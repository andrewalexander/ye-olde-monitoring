# services.dnscount.guard: fail2ban jails over Caddy's JSON access log, so
# scanners get banned at the firewall, and dnscount-fail2ban records each ban
# for `dnscount report bans` (which checks that it held).
#
# Also defines services.dnscount.caddyLog.format, the body of a Caddy `log {}`
# block that writes the log these jails (and dnscount-caddy-log) read, with
# credentials stripped before they reach disk.
{ config, lib, ... }:

let
  inherit (lib) mkOption mkEnableOption mkIf types concatStringsSep;
  cfg = config.services.dnscount.guard;
  logPath = config.services.dnscount.caddyLog.path;

  # Each log line is one JSON object with request.client_ip (the real visitor,
  # once Caddy is the only proxy) before request.uri, and status after the
  # request. Only the path is matched, not the query string, so a search term
  # can't trip a jail.
  pathRegex = paths: ''"uri":"(?i:[^"?]*(?:${concatStringsSep "|" paths}))'';
  probeRegex = paths: ''"client_ip":"<HOST>",.*?${pathRegex paths}'';
  notFoundSkip = lib.optionalString (cfg.notFoundIgnore != [ ])
    "(?!/(?i:${concatStringsSep "|" cfg.notFoundIgnore})/)";
  notFoundRegex = ''"client_ip":"<HOST>",.*?"uri":"${notFoundSkip}[^"]*",.*"status":404\b'';
  unauthorizedRegex = ''"client_ip":"<HOST>",.*"status":401\b'';

  # dnscount logs this when a breaker trips (forensics.TripLine; a Go test
  # reads this line, so keep it on one line).
  tripRegex = ''breaker trip: breaker=(?:${concatStringsSep "|" cfg.tripBreakers}) ip=<HOST> reason='';

  caddyJail = { failregex, maxretry, findtime, bantime }: {
    filter.Definition = {
      inherit failregex;
      datepattern = ''"ts":{EPOCH}'';
    };
    settings = {
      backend = "polling";
      logpath = cfg.accessLog;
      port = cfg.ports;
      inherit maxretry findtime bantime;
    };
  };
in
{
  options.services.dnscount = {
    caddyLog.format = mkOption {
      type = types.str;
      readOnly = true;
      description = ''
        The inside of a Caddy `log {}` block (use it as a virtual host's
        `logFormat`). It writes the JSON access log that dnscount-caddy-log
        tails and the guard's jails read, mode 640, with credential query
        parameters and auth headers removed. dnscount redacts the same keys
        again on ingest.
      '';
      default = ''
        output file ${logPath} {
          mode 640
        }
        format filter {
          request>uri query {
            replace api_key REDACTED
            replace ApiKey REDACTED
            replace X-Emby-Token REDACTED
            replace token REDACTED
          }
          request>headers>Referer regexp "(?i)(api_?key|token)=[^&#]*" "$1=REDACTED"
          request>headers>X-Emby-Authorization delete
          request>headers>X-Emby-Token delete
          request>headers>X-Mediabrowser-Token delete
          wrap json
        }
      '';
    };

    guard = {
      enable = mkEnableOption ''
        fail2ban jails over Caddy's access log: paths no real client asks for
        (`caddy-probe-certain`, `caddy-probe`), and bursts of 404s (`caddy-404`) or 401s (`caddy-401`); and over dnscount's
        journal: any address that trips a breaker (`dnscount-trip`). Repeat offenders get
        longer bans, across all jails. With an HTTP-proxy VPS in front, the
        firewall here only sees the VPS, so a ban would block everyone: ban on
        the VPS instead'';

      accessLog = mkOption {
        type = types.str;
        default = logPath;
        defaultText = lib.literalExpression "config.services.dnscount.caddyLog.path";
        description = "Caddy JSON access log the jails read (written with `caddyLog.format`).";
      };

      ports = mkOption {
        type = types.str;
        default = "80,443";
        example = "80,443,8096";
        description = "Ports a ban blocks: every port Caddy serves the public on.";
      };

      exempt = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "192.168.1.0/24" ];
        description = "Networks never banned, so a mistyped password at home can't lock you out.";
      };

      probePathsCertain = mkOption {
        type = types.listOf types.str;
        description = ''
          Regex alternatives for paths no legitimate client ever asks for,
          not even once: one hit is a day's ban (`caddy-probe-certain`).
          fail2ban's config parser reads % as interpolation, so write %% for
          one %.
        '';
        default = [
          # dot-directories and dotfiles (.env, .git, .aws, .ssh)
          ''/\.(?!well-known/)''
          # secrets by extension
          ''\.(?:env|pem|key|enc)(?=[/"?]|$)''
          # cloud and app credential files (not config.json: Jellyfin's web client loads one)
          ''/(?:aws|appsettings[^/"?]*|credentials|secrets?|service-account)\.json''
          # admin panels and exploit endpoints
          ''wp-|phpmyadmin|phpinfo|cgi-bin|_vti_|_ignition''
          # path traversal
          ''%%2e|%%5c|\.\.''
          ''/(?:etc|proc|root|var/task)/''
        ];
      };

      probePaths = mkOption {
        type = types.listOf types.str;
        description = ''
          Regex alternatives for paths no legitimate client asks for, but
          that are less certain than `probePathsCertain`. Two hits in a day
          is a day's ban (`caddy-probe`). fail2ban's config parser reads % as
          interpolation, so write %% for one %.
        '';
        default = [
          # server-side scripts and config files
          ''\.(?:php\d?|phtml|cgi|pl|aspx?|axd|jsp|action|ini|ya?ml|toml|tfstate|tfvars|hcl|sql|bak|old|sh|py|rb|cfg|conf|properties|secret|md|log|dist)(?=[/"?]|$)''
          # framework debug endpoints and PHP dependencies
          ''webmin|actuator|_profiler|server-status|telescope|@vite|/vendor/(?:phpunit|composer|autoload)''
          # backups, lockfiles and manifests
          ''backup\.(?:zip|tar|tgz|gz|rar|7z)''
          ''/(?:package-lock|composer)\.json|(?:yarn|bun|Gemfile|Pipfile|composer)\.lock|/go\.sum|requirements\.txt''
          ''/config\.xml|/node_modules/''
        ];
      };

      notFoundIgnore = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "items" "users" "web" ];
        description = ''
          First path segments where the app's own clients get 404s in normal
          use (a missing poster, a stale client file). 404s under them don't
          count toward `caddy-404`. Elsewhere a real client rarely sees one,
          and a scanner guessing paths sees hundreds.
        '';
      };

      tripBreakers = mkOption {
        type = types.listOf types.str;
        default = [ "ingest" ];
        example = [ "ingest" "syslog" ];
        description = ''
          Breakers whose trips ban the address (`dnscount-trip` jail, from
          dnscount's journal). ingest is what the public reaches (the counter
          only reads, so it has no breaker); syslog and syslog-not-allowed
          only ever see the LAN.
        '';
      };

      extraJails = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        example = lib.literalExpression ''
          {
            jellyfin = {
              filter.Definition.failregex = "Authentication request for .* has been denied \\(IP: <HOST>\\)";
              settings = { journalmatch = "_SYSTEMD_UNIT=jellyfin.service"; port = "80,443"; maxretry = 5; findtime = "10m"; bantime = "1h"; };
            };
          }
        '';
        description = "More `services.fail2ban.jails`, such as an app's failed-login jail. They share the escalating bans.";
      };
    };
  };

  config = mkIf cfg.enable {
    # The stock iptables-multiport action, except a banned address's packets
    # also get a kernel log line ("f2b-<jail>: ... SRC=... DPT=...") before
    # they're rejected, so dnscount-banned-traffic can record who keeps
    # knocking. Rate-limited per source address (not one bucket for
    # everyone, like iptables-multiport-log), so one flood can't hide the
    # rest; past the limit a packet is still rejected, just not logged.
    environment.etc."fail2ban/action.d/dnscount-iptables-log.conf".text = ''
      [INCLUDES]
      before = iptables.conf

      [Definition]
      type = multiport
      actionstart = <known/actionstart>
                    { <iptables> -N f2b-<name>-log 2>/dev/null; <iptables> -F f2b-<name>-log; }
                    <iptables> -A f2b-<name>-log -m hashlimit --hashlimit-upto <loglimit> --hashlimit-burst <logburst> --hashlimit-mode srcip --hashlimit-name f2b-log -j LOG --log-level info --log-prefix "$(expr 'f2b-<name>' : '\(.\{1,26\}\)'): "
                    <iptables> -A f2b-<name>-log -j <blocktype>
      actionstop = <known/actionstop>
                   <iptables> -F f2b-<name>-log
                   <iptables> -X f2b-<name>-log
      actionban = <iptables> -I f2b-<name> 1 -s <ip> -j f2b-<name>-log
      actionunban = <iptables> -D f2b-<name> -s <ip> -j f2b-<name>-log

      [Init]
      loglimit = 12/min
      logburst = 12
    '';

    services.fail2ban = {
      enable = true;
      banaction = "dnscount-iptables-log";
      ignoreIP = cfg.exempt;
      # Each new ban of the same IP lasts twice as long as the last, up to a
      # week, whichever jail it lands in.
      bantime-increment = {
        enable = true;
        maxtime = "1w";
        overalljails = true;
      };
      # How long fail2ban remembers past bans. The 1-day default forgets a
      # scanner before it usually comes back, so the doubling above would
      # start over at the base ban each time.
      daemonSettings.Definition.dbpurgeage = "30d";
      jails = {
        caddy-probe-certain = caddyJail {
          failregex = probeRegex cfg.probePathsCertain;
          maxretry = 1;
          findtime = "1h";
          bantime = "1d";
        };
        # A day's window: scanners often come back hours later. A path the
        # jail above already bans for isn't counted twice.
        caddy-probe = lib.recursiveUpdate (caddyJail {
          failregex = probeRegex cfg.probePaths;
          maxretry = 2;
          findtime = "1d";
          bantime = "1d";
        }) { filter.Definition.ignoreregex = pathRegex cfg.probePathsCertain; };
        # The looser of the two signals, so a shorter ban.
        caddy-404 = caddyJail {
          failregex = notFoundRegex;
          maxretry = 20;
          findtime = "10m";
          bantime = "1h";
        };
        # Token guessing and unauthenticated scraping. An app's own log often
        # has no address for these (Jellyfin logs "Invalid token" without one),
        # but Caddy's does. A client with an expired token gets a few, not 20.
        caddy-401 = caddyJail {
          failregex = unauthorizedRegex;
          maxretry = 20;
          findtime = "10m";
          bantime = "1h";
        };
        # A breaker trip is already a burst well past normal use: ban at once.
        dnscount-trip = {
          filter.Definition.failregex = tripRegex;
          settings = {
            backend = "systemd";
            journalmatch = "_SYSTEMD_UNIT=dnscount-serve.service + _SYSTEMD_UNIT=dnscount-syslog.service";
            port = cfg.ports;
            maxretry = 1;
            findtime = "10m";
            bantime = "1h";
          };
        };
      } // cfg.extraJails;
    };

    # fail2ban won't start if a jail's log file is missing, and Caddy creates
    # its access log when it loads its config.
    systemd.services.fail2ban = {
      after = [ "caddy.service" ];
      wants = [ "caddy.service" ];
    };
  };
}
