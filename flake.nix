{
  description = "ye-olde-monitoring: watch what connects to the things you expose, and what your network looks up";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      linux = [ "x86_64-linux" "aarch64-linux" ];
    in
    {
      packages = forAll (pkgs: rec {
        dnscount = pkgs.callPackage ./nix/package.nix { };
        default = dnscount;
      });

      # In a host's flake:
      #   inputs.monitoring.url = "github:andrewalexander/ye-olde-monitoring";
      #   modules = [ monitoring.nixosModules.default { services.dnscount.enable = true; } ];
      # services.dnscount, plus services.dnscount.guard (fail2ban over Caddy's log).
      nixosModules.default = { lib, pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        services.dnscount.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.dnscount;
      };

      # Boot VMs (need KVM): nix build .#checks.x86_64-linux.module
      checks = nixpkgs.lib.genAttrs linux (system: {
        module = nixpkgs.legacyPackages.${system}.testers.runNixOSTest (import ./nix/test.nix self);
        guard = nixpkgs.legacyPackages.${system}.testers.runNixOSTest (import ./nix/test-guard.nix self);
      });
    };
}
