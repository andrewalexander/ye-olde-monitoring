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
    };
    environment.systemPackages = [ pkgs.curl pkgs.netcat ];
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

    machine.succeed("systemctl start dnscount-backup.service")
    machine.succeed("ls /var/lib/dnscount/backups | grep -q .")
  '';
}
