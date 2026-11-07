# VM test for nixosModules.default: nix build .#checks.x86_64-linux.module
self:
{
  name = "dnscount-module";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    services.dnscount = {
      enable = true;
      syslog = {
        enable = true;
        address = "127.0.0.1";
        allow = [ "127.0.0.1" ];
      };
      # No internet in the VM: the only feed is a local file.
      explore = {
        enable = true;
        feeds.disable = [ "feodo" "spamhaus-drop" "spamhaus-drop6" "hagezi-tif" "firehol1" "hagezi-tif-ips"
          "tor-exits" "openphish" "stevenblack" "iptoasn" ];
        feeds.extra.vmbad = { url = "/etc/dnscount-vm-bad.txt"; interval = "1m"; };
      };
      # Outside services, faked: a local InternetDB that knows one address.
      lookups = {
        enable = true;
        automatic = [ "internetdb" ];
        providers.internetdb.base = "http://127.0.0.1:9911";
        neverLookup = [ "ourname.test" ];
      };
    };
    environment.etc."dnscount-vm-bad.txt".text = "203.0.113.66\n";
    systemd.services.fake-internetdb = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 9911 --bind 127.0.0.1 --directory ${
        pkgs.writeTextDir "8.8.4.4" ''{"cpes":[],"hostnames":["dns.google"],"ip":"8.8.4.4","ports":[53,443],"tags":[],"vulns":[]}''
      }";
    };
    environment.systemPackages = [ pkgs.curl pkgs.netcat pkgs.jq ];
  };

  testScript = ''
    machine.wait_for_unit("dnscount-serve.service")
    machine.wait_for_open_port(8080)
    machine.succeed("curl -sf 'http://127.0.0.1:8080/counter.txt?site=vm' | grep -x 1")
    machine.succeed("curl -sf http://127.0.0.1:8081/api/health")

    # The admin API must not listen beyond localhost.
    machine.fail("ss -ltnH | awk '{print $4}' | grep -E ':8081$' | grep -v '^127.0.0.1:'")

    machine.wait_for_unit("dnscount-syslog.service")
    machine.wait_until_succeeds("ss -lunH | grep -q '127.0.0.1:5514'")
    machine.succeed(
        "echo '<30>Oct 27 15:00:00 router dnsmasq[1]: query[A] vm.example.org from 192.168.1.20'"
        " | nc -u -w1 127.0.0.1 5514"
    )
    machine.wait_until_succeeds("dnscount-admin report dns -domain vm.example.org | grep -q 192.168.1.20")
    machine.succeed("test -n \"$(ls /var/lib/dnscount/raw)\"")

    # A UniFi IPS event, as the Network app sends it to a SIEM server.
    machine.succeed(
        "echo '<14>Oct 27 15:01:00 router CEF:0|Ubiquiti|UniFi Network|10.0|545|Threat Detected and Blocked|7|"
        "src=203.0.113.7 spt=51234 dst=192.168.1.10 dpt=443 proto=TCP UNIFIipsSignature=ET SCAN vm test "
        "UNIFIipsSignatureId=2010937 UNIFIipsClass=Potentially Bad Traffic'"
        " | nc -u -w1 127.0.0.1 5514"
    )
    machine.wait_until_succeeds("dnscount-admin report alerts -action blocked | grep 203.0.113.7 | grep -q 'ET SCAN vm test'")

    # The explorer: a separate process reading the live database read-only.
    machine.wait_for_unit("dnscount-explore.service")
    machine.wait_for_open_port(8090)
    machine.fail("ss -ltnH | awk '{print $4}' | grep -E ':8090$' | grep -v '^127.0.0.1:'")
    machine.succeed("curl -fsS http://127.0.0.1:8090/ | grep -q 'dnscount explorer'")
    # Writes to the live database show up through its read-only view at once.
    machine.succeed(
        "printf '%s\\n%s\\n' '<30>Oct 27 15:02:00 router dnsmasq[1]: query[A] evil.example.org from 192.168.1.20'"
        " '<30>Oct 27 15:02:00 router dnsmasq[1]: reply evil.example.org is 203.0.113.66' | nc -u -w1 127.0.0.1 5514"
    )
    machine.wait_until_succeeds("curl -fsS 'http://127.0.0.1:8090/api/domain/evil.example.org' | jq -e '.lookups[0].client_ip == \"192.168.1.20\"'")
    # The local feed is "downloaded", and the explorer picks it up and matches.
    machine.succeed("systemctl start dnscount-feeds.service")
    machine.succeed("test -s /var/lib/dnscount/feeds/vmbad.txt")
    machine.succeed("systemctl restart dnscount-explore.service")
    machine.wait_until_succeeds(
        "curl -fsS 'http://127.0.0.1:8090/api/flagged?since=1000d'"
        " | jq -e '.[] | select(.indicator == \"203.0.113.66\" and .direction == \"out\" and .clients[0].ip == \"192.168.1.20\")'",
        timeout=60,
    )
    # The explorer can read its cgroup numbers under the sandbox.
    machine.wait_until_succeeds(
        "curl -fsS http://127.0.0.1:8090/api/health | jq -e '.now.units[\"dnscount-serve\"].mem_bytes > 0'", timeout=60)
    machine.succeed("curl -fsS http://127.0.0.1:8090/api/health | jq -e '.breakers | length == 2'")
    score = float(machine.succeed("systemd-analyze security dnscount-explore.service --no-pager | tail -1 | grep -oE '[0-9]+\\.[0-9]+'").strip())
    assert score <= 3.0, score

    # Outside services: an IPS alert from a public address makes it worth
    # asking about; the hourly unit asks the (fake) InternetDB, and the
    # explorer shows the answer. The VM's documentation addresses are never
    # sent (the privacy gate refuses them).
    machine.wait_for_unit("fake-internetdb.service")
    machine.wait_for_open_port(9911)
    stamp = machine.succeed("date -u '+%b %d %H:%M:%S'").strip()
    machine.succeed(
        f"echo '<14>{stamp} router CEF:0|Ubiquiti|UniFi Network|10.0|545|Threat Detected and Blocked|7|"
        "src=8.8.4.4 spt=5000 dpt=443 proto=TCP UNIFIipsSignature=ET SCAN vm lookup UNIFIipsSignatureId=1'"
        " | nc -u -w1 127.0.0.1 5514"
    )
    machine.wait_until_succeeds("dnscount-admin report alerts | grep -q 8.8.4.4")
    out = machine.succeed("dnscount-admin enrich -provider internetdb -dry-run -since 10000h")
    print(out)
    asked = out.split("internetdb:")[1]
    assert "8.8.4.4" in asked and "203.0.113" not in asked, out
    machine.succeed("systemctl start dnscount-lookups.service")
    machine.succeed(
        "curl -fsS 'http://127.0.0.1:8090/api/ip/8.8.4.4' | jq -e '.intel.queried.internetdb.found == true'"
    )
    machine.succeed("curl -fsS http://127.0.0.1:8090/api/health | jq -e '.lookups[0].provider == \"internetdb\"'")
    # Run again: cached, nothing re-asked.
    machine.succeed("systemctl start dnscount-lookups.service")
    machine.succeed("curl -fsS http://127.0.0.1:8090/api/health | jq -e '.lookups[0].units_24h == 1'")

    machine.succeed("systemctl start dnscount-backup.service")
    machine.succeed("ls /var/lib/dnscount/backups | grep -q .")
  '';
}
