# VM test for services.dnscount.guard over a bare Caddy site:
#   nix build .#checks.x86_64-linux.guard
self:
let
  # The test framework numbers nodes on eth1 in name order.
  attacker = "192.168.1.1";
  client = "192.168.1.2";
  server = "192.168.1.3";

  tools = { pkgs, ... }: {
    environment.systemPackages = [ pkgs.curl ];
    networking.firewall.enable = false;
  };
in
{
  name = "dnscount-guard";

  nodes.attacker = tools;
  nodes.client = tools;

  nodes.server = { config, pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.dnscount = {
      enable = true;
      caddyLog.enable = true;
      # Reachable directly so the attacker can trip the ingest breaker. The
      # counter is for the Caddy site below (its log names it by the host).
      serve.addr = "0.0.0.0:8080";
      serve.extraArgs = [ "-counter-ttl" "1s" ];
      counterSites = [ server ];
      # Bans are read back through the explorer's API. No internet: no feeds.
      explore = {
        enable = true;
        feeds.disable = [ "feodo" "spamhaus-drop" "spamhaus-drop6" "hagezi-tif" "firehol1" "hagezi-tif-ips"
          "tor-exits" "openphish" "stevenblack" "iptoasn" ];
      };
      guard = {
        enable = true;
        ports = "80";
        exempt = [ "${client}/32" ];
        notFoundIgnore = [ "web" ];
      };
    };
    services.caddy = {
      enable = true;
      virtualHosts."http://:80" = {
        logFormat = config.services.dnscount.caddyLog.format;
        extraConfig = ''
          respond /ok "ok" 200
          respond /auth 401
          respond 404
        '';
      };
    };
    networking.firewall.allowedTCPPorts = [ 80 8080 ];
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
  };

  testScript = ''
    start_all()
    server.wait_for_unit("caddy.service")
    server.wait_for_unit("fail2ban.service")
    server.wait_for_unit("dnscount-serve.service")
    client.wait_until_succeeds("curl -fsS --max-time 5 http://${server}/ok", timeout=60)
    attacker.succeed("curl -fsS --max-time 5 http://${server}/ok")

    with subtest("the counter counts page loads from Caddy's log, once per visitor"):
        for _ in range(3):
            client.succeed("curl -fsS --max-time 5 -o /dev/null http://${server}/ok")
        server.wait_until_succeeds("curl -fsS 'http://127.0.0.1:8080/counter.txt?site=${server}' | grep -x 2", timeout=30)

    def unban(jail):
        server.succeed(f"fail2ban-client set {jail} unbanip ${attacker}")
        attacker.wait_until_succeeds("curl -fsS --max-time 5 http://${server}/ok", timeout=30)

    with subtest("404s under an ignored path don't count, and probes get banned"):
        # Well past caddy-404's limit of 20, but under /web/.
        for i in range(25):
            attacker.succeed(f"curl -sS --max-time 5 -o /dev/null http://${server}/web/missing-{i}.js")
        for path in ["/.env", "/.git/config"]:
            attacker.succeed(f"curl -sS --max-time 5 -o /dev/null http://${server}{path}")
        server.wait_until_succeeds("fail2ban-client status caddy-probe | grep -q '${attacker}'", timeout=60)
        # By now fail2ban has read past the 404s above.
        out = server.succeed("fail2ban-client status caddy-404")
        assert "${attacker}" not in out, out
        attacker.fail("curl -sS --max-time 5 http://${server}/ok")
        unban("caddy-probe")

    with subtest("a burst of other 404s gets banned"):
        for i in range(21):
            attacker.succeed(f"curl -sS --max-time 5 -o /dev/null http://${server}/guess-{i}")
        server.wait_until_succeeds("fail2ban-client status caddy-404 | grep -q '${attacker}'", timeout=60)
        attacker.fail("curl -sS --max-time 5 http://${server}/ok")
        unban("caddy-404")

    with subtest("a burst of 401s gets banned"):
        for i in range(21):
            attacker.succeed("curl -sS --max-time 5 -o /dev/null http://${server}/auth")
        server.wait_until_succeeds("fail2ban-client status caddy-401 | grep -q '${attacker}'", timeout=60)
        attacker.fail("curl -sS --max-time 5 http://${server}/ok")
        unban("caddy-401")

    with subtest("tripping a dnscount breaker gets banned"):
        # No token: each POST is a bad request, and 10 a minute trips it.
        for i in range(12):
            attacker.succeed("curl -sS --max-time 5 -o /dev/null -X POST -d '{}' http://${server}:8080/ingest")
        server.wait_until_succeeds("journalctl -u dnscount-serve.service | grep -q 'breaker trip: breaker=ingest ip=${attacker}'", timeout=30)
        server.wait_until_succeeds("fail2ban-client status dnscount-trip | grep -q '${attacker}'", timeout=60)
        attacker.fail("curl -sS --max-time 5 http://${server}/ok")
        unban("dnscount-trip")

    with subtest("exempt networks are never banned"):
        for path in ["/.env", "/.git/config", "/wp-login.php"]:
            client.succeed(f"curl -sS --max-time 5 -o /dev/null http://${server}{path}")
        server.sleep(5)
        out = server.succeed("fail2ban-client status caddy-probe")
        assert "${client}" not in out, out
        client.succeed("curl -fsS --max-time 5 http://${server}/ok")

    with subtest("dnscount records both bans, and neither leaked"):
        server.wait_for_unit("dnscount-fail2ban.service")
        server.wait_for_open_port(8090)
        bans = "curl -fsS http://127.0.0.1:8090/api/bans?ip=${attacker}"
        # Each ban paired with its unban, and the jail's ports carried over.
        for jail in ["caddy-probe", "caddy-404"]:
            server.wait_until_succeeds(
                f"{bans} | jq -e 'map(select(.jail == \"{jail}\" and .unbanned_at != null and .ports == \"80\")) | length == 1'",
                timeout=60,
            )
        print(server.succeed("dnscount-admin report bans"))
        server.succeed(f"{bans} | jq -e 'all(.hits_during == 0)'")
        # Reading the whole journal again (as every restart does) adds nothing.
        before = server.succeed("dnscount-admin report bans | wc -l")
        server.succeed("systemctl restart dnscount-fail2ban.service")
        server.sleep(5)
        assert server.succeed("dnscount-admin report bans | wc -l") == before
  '';
}
