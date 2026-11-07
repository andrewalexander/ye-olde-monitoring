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
  probeRegex = ''"client_ip":"<HOST>",.*?"uri":"(?i:[^"?]*(?:${concatStringsSep "|" cfg.probePaths}))'';
  notFoundSkip = lib.optionalString (cfg.notFoundIgnore != [ ])
    "(?!/(?i:${concatStringsSep "|" cfg.notFoundIgnore})/)";
  notFoundRegex = ''"client_ip":"<HOST>",.*?"uri":"${notFoundSkip}[^"]*",.*"status":404\b'';

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
        (`caddy-probe`), and bursts of 404s (`caddy-404`); and over dnscount's
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

      probePaths = mkOption {
        type = types.listOf types.str;
        description = ''
          Regex alternatives for paths no legitimate client asks for. Two hits
          in an hour is a day's ban. fail2ban's config parser reads % as
          interpolation, so write %% for one %.
        '';
        default = [
          # dot-directories (.env, .git, .aws)
          ''/\.(?!well-known/)''
          # server-side scripts and config files
          ''\.(?:php\d?|phtml|cgi|pl|aspx?|axd|jsp|action|env|ini|ya?ml|toml|tfstate|tfvars|hcl|sql|bak|old|sh|py|rb|cfg|conf|properties|secret|key|md)(?=[/"?]|$)''
          # admin panels and framework debug endpoints
          ''wp-|phpmyadmin|cgi-bin|webmin|actuator|_profiler|server-status|telescope|@vite|/vendor/''
          # path traversal
          ''%%2e|%%5c|\.\.''
          ''/(?:etc|proc|root|var/task)/''
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
        default = [ "counter" "ingest" ];
        example = [ "counter" "ingest" "syslog" ];
        description = ''
          Breakers whose trips ban the address (`dnscount-trip` jail, from
          dnscount's journal). counter and ingest are what the public reaches;
          syslog and syslog-not-allowed only ever see the LAN.
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
    services.fail2ban = {
      enable = true;
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
        caddy-probe = caddyJail {
          failregex = probeRegex;
          maxretry = 2;
          findtime = "1h";
          bantime = "1d";
        };
        # The looser of the two signals, so a shorter ban.
        caddy-404 = caddyJail {
          failregex = notFoundRegex;
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
