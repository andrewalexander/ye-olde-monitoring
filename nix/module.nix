# services.dnscount: the NixOS equivalent of deploy/install.sh + deploy/systemd.
# Unit hardening matches deploy/systemd/*.service; keep the two in step.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption mkEnableOption mkIf types concatStringsSep;
  cfg = config.services.dnscount;
  dataDir = "/var/lib/dnscount";
  db = "${dataDir}/dnscount.db";
  bin = lib.getExe cfg.package;

  hardening = {
    User = "dnscount";
    Group = "dnscount";
    StateDirectory = "dnscount";
    StateDirectoryMode = "0750";
    UMask = "0027";
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    SystemCallFilter = [ "@system-service" "~@privileged" ];
    # Refuse (not kill) anything else; the Go runtime probes some syscalls.
    SystemCallErrorNumber = "EPERM";
  };
  network = { RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ]; };
  noNetwork = { PrivateNetwork = true; RestrictAddressFamilies = [ "AF_UNIX" ]; };

  isV6 = a: lib.hasInfix ":" a;

  # Each jail's port setting, so a ban only counts requests on ports it
  # actually blocks. Jails without one cover every port.
  jailPorts = concatStringsSep ";" (lib.mapAttrsToList (name: j: "${name}=${toString j.settings.port}")
    (lib.filterAttrs (_: j: builtins.isAttrs j && (j.settings or { }) ? port) config.services.fail2ban.jails));
  syslogListen = "udp://${cfg.syslog.address}:${toString cfg.syslog.port}";

  # The lookups config: caps, which providers run on their own, our own domains.
  lookupsConfig = pkgs.writeText "dnscount-lookups.json" (builtins.toJSON {
    never = cfg.lookups.neverLookup;
    automatic = cfg.lookups.automatic;
    providers = lib.mapAttrs (_: c: lib.filterAttrs (_: v: v != null) c) cfg.lookups.providers;
  });
  # What dnscount-admin and dnscount-lookups both see.
  lookupsEnv = lib.optionalString cfg.lookups.enable (
    "DNSCOUNT_LOOKUPS_CONFIG=${lookupsConfig}"
    + lib.optionalString (cfg.lookups.keyFile != null) " DNSCOUNT_KEY_FILE=${cfg.lookups.keyFile}"
  );

  # Feed flags shared by the explorer and the downloader.
  feedArgs = lib.optionals (cfg.explore.feeds.disable != [ ]) [ "-feeds-disable" (concatStringsSep "," cfg.explore.feeds.disable) ]
    ++ lib.optionals (cfg.explore.feeds.extra != { }) [
      "-feeds-file"
      (pkgs.writeText "dnscount-feeds.json" (builtins.toJSON
        (lib.mapAttrsToList (name: f: f // { inherit name; }) cfg.explore.feeds.extra)))
    ];
in
{
  options.services.dnscount = {
    enable = mkEnableOption "dnscount (counter, /ingest and the admin API)";

    package = mkOption {
      type = types.package;
      description = "The dnscount package.";
    };

    environmentFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/var/lib/secrets/dnscount.env";
      description = ''
        File with `DNSCOUNT_TOKEN=<token>`, the bearer token for POST /ingest.
        Kept out of the Nix store (which is world-readable). Without it,
        /ingest rejects everything; the counter still works.
      '';
    };

    trustedProxies = mkOption {
      type = types.listOf types.str;
      default = [ "127.0.0.1/32" "::1/128" ];
      description = ''
        Peers whose X-Forwarded-For is believed. Add the VPS (or its tunnel
        subnet) here when a proxy sits in front of this host's Caddy.
      '';
    };

    serve = {
      addr = mkOption {
        type = types.str;
        default = "127.0.0.1:8080";
        description = "Public listener (counter + /ingest), usually behind Caddy.";
      };
      adminAddr = mkOption {
        type = types.str;
        default = "127.0.0.1:8081";
        description = "Admin API listener. It has no auth: keep it on localhost.";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "-counter-limit" "60" ];
        description = "Extra flags for `dnscount serve`.";
      };
    };

    caddyLog = {
      enable = mkEnableOption "recording every request Caddy serves (tails its JSON access log)";
      path = mkOption {
        type = types.str;
        default = "/var/log/caddy/access.log";
        description = "Caddy JSON access log. Caddy must write it readable by its group (log mode 640).";
      };
      group = mkOption {
        type = types.str;
        default = config.services.caddy.group;
        defaultText = lib.literalExpression "config.services.caddy.group";
        description = "Group that can read the access log.";
      };
    };

    syslog = {
      enable = mkEnableOption "the router syslog receiver (DNS lookups + firewall lines)";
      address = mkOption {
        type = types.str;
        default = "0.0.0.0";
        example = "192.168.1.10";
        description = "Address to listen on. The LAN IP keeps it off other interfaces.";
      };
      port = mkOption {
        type = types.port;
        default = 5514;
      };
      allow = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "192.168.1.1" ];
        description = "Source IPs/CIDRs allowed to send (the router). Required.";
      };
      keepRaw = mkOption {
        type = types.bool;
        default = true;
        description = "Keep every received line in daily files under ${dataDir}/raw, for re-ingesting.";
      };
      openFirewall = mkOption {
        type = types.bool;
        default = true;
        description = "Open the UDP port in the firewall, for the `allow` sources only.";
      };
    };

    fail2ban = {
      enable = mkOption {
        type = types.bool;
        default = config.services.fail2ban.enable;
        defaultText = lib.literalExpression "config.services.fail2ban.enable";
        description = ''
          Record fail2ban's bans and unbans, read from its journal, so
          `dnscount report bans` can check that each ban held. fail2ban itself
          is left alone: dnscount reads its log as the dnscount user.
        '';
      };
    };

    explore = {
      enable = mkEnableOption ''
        the explorer: a separate, low-priority process serving the LAN table UI
        and its API from a read-only view of the database, with free threat
        feeds matched locally (see docs/homelab.md)
      '';
      addr = mkOption {
        type = types.str;
        default = "127.0.0.1:8090";
        description = "Where the explorer listens. No auth: only Caddy's LAN-only site should reach it.";
      };
      queryTimeout = mkOption {
        type = types.str;
        default = "10s";
        description = "Per-request query deadline, so no page keeps a read open for long.";
      };
      feeds = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Download the threat feeds and the IP-to-ASN table hourly (each feed only when it's due).";
        };
        disable = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "stevenblack" ];
          description = "Built-in feeds to leave out (dnscount feeds list shows them).";
        };
        extra = mkOption {
          type = types.attrsOf (types.submodule {
            options = {
              url = mkOption {
                type = types.str;
                description = "URL or local path. {ENV_VAR} is filled from environmentFile, e.g. {ABUSECH_AUTH_KEY}.";
              };
              kind = mkOption { type = types.enum [ "ip" "domain" ]; default = "ip"; };
              format = mkOption { type = types.enum [ "plain" "hosts" "url" "spamhaus" ]; default = "plain"; };
              verdict = mkOption { type = types.enum [ "malicious" "suspicious" "info" ]; default = "malicious"; };
              interval = mkOption { type = types.str; default = "6h"; };
              about = mkOption { type = types.str; default = ""; };
            };
          });
          default = { };
          example = lib.literalExpression ''{ mine = { url = "/etc/dnscount/bad-ips.txt"; interval = "10m"; }; }'';
          description = "Your own feeds. A name matching a built-in one replaces it.";
        };
        environmentFile = mkOption {
          type = types.nullOr types.path;
          default = null;
          example = "/var/lib/secrets/dnscount-feeds.env";
          description = "File outside the Nix store with keys for feed URLs, e.g. ABUSECH_AUTH_KEY=....";
        };
      };
    };

    lookups = {
      enable = mkEnableOption ''
        asking outside services about flagged, banned and alerting addresses (and
        flagged domains): Shodan InternetDB and AbuseIPDB hourly, on their own,
        within their caps; Censys only when you run
        `dnscount-admin enrich -provider censys`. Answers are cached in the
        explorer's enrichment store. Nothing describing the LAN is ever sent
      '';
      automatic = mkOption {
        type = types.listOf (types.enum [ "internetdb" "abuseipdb" ]);
        default = [ "internetdb" "abuseipdb" ];
        description = "Providers the hourly run asks. Censys is never automatic: it spends credits.";
      };
      keyFile = mkOption {
        # A string, not a path: a path would be copied into the world-readable
        # Nix store.
        type = types.nullOr types.str;
        default = null;
        example = "/var/lib/dnscount/lookups.env";
        description = ''
          KEY=value file with ABUSE_IPDB_KEY and CENSYS_TOKEN, outside the Nix
          store, readable by the dnscount user: mode 0640, root:dnscount, in a
          directory it can enter (/var/lib/dnscount is; a root-only
          /var/lib/secrets isn't). Missing: only keyless providers run.
        '';
      };
      neverLookup = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "example.com" ];
        description = "Our own domains (and their subdomains): never sent to any provider.";
      };
      providers = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            daily = mkOption { type = types.nullOr types.ints.unsigned; default = null; description = "Units in any 24 hours."; };
            monthly = mkOption { type = types.nullOr types.ints.unsigned; default = null; description = "Units this calendar month (UTC)."; };
            ttl = mkOption { type = types.nullOr types.str; default = null; example = "168h"; description = "Re-ask after this long."; };
            base = mkOption { type = types.nullOr types.str; default = null; description = "API base URL (for tests)."; };
          };
        });
        default = { };
        example = lib.literalExpression ''{ censys.monthly = 50; }'';
        description = ''
          Caps per provider, over the defaults: internetdb 500 a day and 7 days
          before re-asking; abuseipdb 800 a day (of the free 1,000), 7 days;
          censys 5 a day and 100 a month, 30 days.
        '';
      };
    };

    backup = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Daily copy of the database to ${dataDir}/backups.";
      };
      keep = mkOption {
        type = types.ints.positive;
        default = 7;
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [{
      assertion = !cfg.syslog.enable || cfg.syslog.allow != [ ];
      message = "services.dnscount.syslog.allow must list the router's IP.";
    }];

    users.users.dnscount = {
      isSystemUser = true;
      group = "dnscount";
      home = dataDir;
      extraGroups = lib.optional cfg.caddyLog.enable cfg.caddyLog.group;
    };
    users.groups.dnscount = { };

    # Reports against the service's database: dnscount-admin report hits -top ip
    # (sudo drops DNSCOUNT_DB, so the wrapper sets it after switching user).
    environment.systemPackages = [
      cfg.package
      (pkgs.writeShellScriptBin "dnscount-admin" ''
        exec /run/wrappers/bin/sudo -u dnscount ${pkgs.coreutils}/bin/env DNSCOUNT_DB=${db} ${lookupsEnv} ${bin} "$@"
      '')
    ];

    systemd.services.dnscount-serve = {
      description = "dnscount hit counter, /ingest collector and admin API";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      environment.DNSCOUNT_DB = db;
      serviceConfig = hardening // network // {
        ExecStart = concatStringsSep " " ([
          bin "serve"
          "-addr" cfg.serve.addr
          "-admin-addr" cfg.serve.adminAddr
          "-trusted-proxies" (concatStringsSep "," cfg.trustedProxies)
        ] ++ map lib.escapeShellArg cfg.serve.extraArgs);
        EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
        Restart = "on-failure";
        RestartSec = 2;
      };
    };

    systemd.services.dnscount-caddy-log = mkIf cfg.caddyLog.enable {
      description = "dnscount: record every request Caddy serves (tails its JSON access log)";
      wants = [ "dnscount-serve.service" ];
      after = [ "dnscount-serve.service" "caddy.service" ];
      wantedBy = [ "multi-user.target" ];
      environment.DNSCOUNT_DB = db;
      serviceConfig = hardening // noNetwork // {
        ExecStart = "${bin} ingest-access -format caddy -follow ${cfg.caddyLog.path}";
        SupplementaryGroups = [ cfg.caddyLog.group ];
        Restart = "always";
        RestartSec = 5;
      };
    };

    systemd.services.dnscount-syslog = mkIf cfg.syslog.enable {
      description = "dnscount: receive the router's syslog (DNS lookups + firewall lines)";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      environment.DNSCOUNT_DB = db;
      serviceConfig = hardening // network // {
        ExecStart = concatStringsSep " " ([
          bin "syslog"
          "-listen" syslogListen
          "-allow" (concatStringsSep "," cfg.syslog.allow)
        ] ++ lib.optionals cfg.syslog.keepRaw [ "-raw" "${dataDir}/raw" ]);
        # Binding a LAN IP fails until DHCP has given it; just retry.
        Restart = "always";
        RestartSec = 2;
      };
    };

    systemd.services.dnscount-fail2ban = mkIf cfg.fail2ban.enable {
      description = "dnscount: record fail2ban's bans and unbans from its journal";
      after = [ "dnscount-serve.service" "fail2ban.service" ];
      wantedBy = [ "multi-user.target" ];
      environment.DNSCOUNT_DB = db;
      # The whole journal is read again on every start; already-recorded
      # lines are skipped, so nothing is lost or doubled across restarts.
      serviceConfig = hardening // noNetwork // {
        ExecStart = pkgs.writeShellScript "dnscount-fail2ban" ''
          set -o pipefail
          ${config.systemd.package}/bin/journalctl --unit=fail2ban.service --output=short-iso \
            --no-pager --follow --lines=all \
            | ${bin} ingest-bans -follow -jail-ports ${lib.escapeShellArg jailPorts} -
        '';
        SupplementaryGroups = [ "systemd-journal" ];
        Restart = "always";
        RestartSec = 5;
      };
    };

    # The explorer only reads dnscount.db (mode=ro), writes only explore.db,
    # and runs at low CPU and IO priority, so it can't hold up ingest. It
    # listens on localhost and never connects out; only dnscount-feeds does.
    systemd.services.dnscount-explore = mkIf cfg.explore.enable {
      description = "dnscount explorer: LAN table UI over a read-only view of the database";
      wants = [ "dnscount-serve.service" ];
      after = [ "dnscount-serve.service" ];
      wantedBy = [ "multi-user.target" ];
      environment.DNSCOUNT_DB = db;
      serviceConfig = hardening // network // {
        ExecStart = concatStringsSep " " ([
          bin "explore"
          "-addr" cfg.explore.addr
          "-query-timeout" cfg.explore.queryTimeout
          "-admin-url" "http://${cfg.serve.adminAddr}"
        ] ++ map lib.escapeShellArg feedArgs);
        IPAddressAllow = [ "localhost" ];
        IPAddressDeny = "any";
        ProtectProc = "invisible";
        Nice = 10;
        CPUWeight = 20;
        IOSchedulingClass = "idle";
        MemoryHigh = "512M";
        MemoryMax = "1G";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };

    # Downloads only the feeds that are due; opens no database.
    # Asks the automatic providers about newly relevant addresses, within their
    # caps. It connects out (to the providers), so it's its own unit; the
    # explorer never does.
    systemd.services.dnscount-lookups = mkIf (cfg.explore.enable && cfg.lookups.enable) {
      description = "dnscount: ask outside services (InternetDB, AbuseIPDB) about flagged addresses";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" "dnscount-explore.service" ];
      environment = {
        DNSCOUNT_DB = db;
        DNSCOUNT_LOOKUPS_CONFIG = "${lookupsConfig}";
      } // lib.optionalAttrs (cfg.lookups.keyFile != null) { DNSCOUNT_KEY_FILE = cfg.lookups.keyFile; };
      serviceConfig = hardening // network // {
        Type = "oneshot";
        ExecStart = "${bin} enrich -auto";
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };
    systemd.timers.dnscount-lookups = mkIf (cfg.explore.enable && cfg.lookups.enable) {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "10m";
        OnCalendar = "hourly";
        RandomizedDelaySec = "10m";
        Persistent = true;
      };
    };

    systemd.services.dnscount-feeds = mkIf (cfg.explore.enable && cfg.explore.feeds.enable) {
      description = "dnscount: download threat feeds and the IP-to-ASN table";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment.DNSCOUNT_DB = db;
      serviceConfig = hardening // network // {
        Type = "oneshot";
        ExecStart = concatStringsSep " " ([ bin "feeds" "update" ] ++ map lib.escapeShellArg feedArgs);
        EnvironmentFile = lib.optional (cfg.explore.feeds.environmentFile != null) cfg.explore.feeds.environmentFile;
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };
    systemd.timers.dnscount-feeds = mkIf (cfg.explore.enable && cfg.explore.feeds.enable) {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2m";
        OnCalendar = "hourly";
        RandomizedDelaySec = "10m";
        Persistent = true;
      };
    };

    systemd.services.dnscount-backup = mkIf cfg.backup.enable {
      description = "dnscount: daily database backup";
      environment.DNSCOUNT_DB = db;
      serviceConfig = hardening // noNetwork // {
        Type = "oneshot";
        ExecStart = "${bin} backup -keep ${toString cfg.backup.keep} ${dataDir}/backups";
      };
    };
    systemd.timers.dnscount-backup = mkIf cfg.backup.enable {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "daily";
        RandomizedDelaySec = "1h";
        Persistent = true;
      };
    };

    # Only the allowed senders get through, not the whole network.
    networking.firewall =
      let
        port = toString cfg.syslog.port;
        v4 = lib.filter (a: !isV6 a) cfg.syslog.allow;
        v6 = lib.filter isV6 cfg.syslog.allow;
        set = l: "{ ${concatStringsSep ", " l} }";
      in
      mkIf (cfg.syslog.enable && cfg.syslog.openFirewall) (
        if config.networking.nftables.enable then {
          extraInputRules = concatStringsSep "\n" (
            lib.optional (v4 != [ ]) "ip saddr ${set v4} udp dport ${port} accept"
            ++ lib.optional (v6 != [ ]) "ip6 saddr ${set v6} udp dport ${port} accept"
          );
        } else {
          extraCommands = concatStringsSep "\n" (
            map (a: "iptables -I nixos-fw -p udp -s ${a} --dport ${port} -j nixos-fw-accept") v4
            ++ map (a: "ip6tables -I nixos-fw -p udp -s ${a} --dport ${port} -j nixos-fw-accept") v6
          );
        }
      );
  };
}
