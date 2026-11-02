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
  syslogListen = "udp://${cfg.syslog.address}:${toString cfg.syslog.port}";
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
        exec /run/wrappers/bin/sudo -u dnscount ${pkgs.coreutils}/bin/env DNSCOUNT_DB=${db} ${bin} "$@"
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
