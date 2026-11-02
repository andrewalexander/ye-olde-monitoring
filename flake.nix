{
  description = "dnscount: hit counter and request/DNS logger backed by one SQLite file";

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
      #   inputs.dnscount.url = "github:<you>/dnscount";   (or path:/...)
      #   modules = [ dnscount.nixosModules.default { services.dnscount.enable = true; } ];
      nixosModules.default = { lib, pkgs, ... }: {
        imports = [ ./nix/module.nix ];
        services.dnscount.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.dnscount;
      };

      # Boots a VM (needs KVM): nix build .#checks.x86_64-linux.module
      checks = nixpkgs.lib.genAttrs linux (system: {
        module = nixpkgs.legacyPackages.${system}.testers.runNixOSTest (import ./nix/test.nix self);
        vpn = nixpkgs.legacyPackages.${system}.testers.runNixOSTest ./nix/test-vpn.nix;
      });
    };
}
